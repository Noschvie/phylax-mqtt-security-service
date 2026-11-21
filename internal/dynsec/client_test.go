// SPDX-License-Identifier: AGPL-3.0-or-later

package dynsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/mqttclient"
)

// fakeBroker records requests and answers them through a handler that
// returns the responses to broadcast (like the plugin, to all subscribers).
type fakeBroker struct {
	mu       sync.Mutex
	requests []map[string]any
	answer   func(req map[string]any) []map[string]any // nil: no response
	err      error                                     // returned by Publish
	block    bool                                      // Publish waits for ctx
	client   *Client
}

func (f *fakeBroker) Publish(ctx context.Context, topic string, payload []byte) error {
	if topic != RequestTopic {
		return fmt.Errorf("unexpected topic %q", topic)
	}
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if f.err != nil {
		return f.err
	}
	var msg struct {
		Commands []map[string]any `json:"commands"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil || len(msg.Commands) != 1 {
		return fmt.Errorf("bad request %s", payload)
	}
	req := msg.Commands[0]
	f.mu.Lock()
	f.requests = append(f.requests, req)
	answer := f.answer
	f.mu.Unlock()
	if answer != nil {
		if rs := answer(req); rs != nil {
			b, _ := json.Marshal(map[string]any{"responses": rs})
			go f.client.HandleMessage(b)
		}
	}
	return nil
}

func newTest(t *testing.T, f *fakeBroker, timeout time.Duration) *Client {
	t.Helper()
	c := NewClient(f, timeout, nil)
	f.client = c
	t.Cleanup(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.pending) != 0 {
			t.Errorf("%d pending requests left", len(c.pending))
		}
	})
	return c
}

func echo(data any) func(map[string]any) []map[string]any {
	return func(req map[string]any) []map[string]any {
		return []map[string]any{{"command": req["command"], "correlationData": req["correlationData"], "data": data}}
	}
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestExecuteRequestAndData(t *testing.T) {
	f := &fakeBroker{answer: echo(map[string]any{"client": map[string]any{"username": "wz-steckdose-tv"}})}
	c := newTest(t, f, time.Second)

	data, err := c.Execute(context.Background(), GetClient{Username: "wz-steckdose-tv"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if string(data) != `{"client":{"username":"wz-steckdose-tv"}}` {
		t.Errorf("data %s", data)
	}
	req := f.requests[0]
	if req["command"] != "getClient" || req["username"] != "wz-steckdose-tv" || len(req) != 3 {
		t.Errorf("request %v", req)
	}
	id, ok := req["correlationData"].(string)
	if !ok || !uuidV4.MatchString(id) {
		t.Errorf("correlationData %v is not a UUID string", req["correlationData"])
	}
}

func TestExecuteOmitsEmptyFields(t *testing.T) {
	f := &fakeBroker{answer: echo(nil)}
	c := newTest(t, f, time.Second)
	if _, err := c.Execute(context.Background(), ListClients{}); err != nil {
		t.Fatal(err)
	}
	if req := f.requests[0]; len(req) != 2 {
		t.Errorf("request %v, want only command and correlationData", req)
	}
}

func TestExecuteCommandError(t *testing.T) {
	f := &fakeBroker{answer: func(req map[string]any) []map[string]any {
		return []map[string]any{{"command": req["command"], "correlationData": req["correlationData"], "error": "Client not found"}}
	}}
	c := newTest(t, f, time.Second)

	_, err := c.Execute(context.Background(), GetClient{Username: "missing"})
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v, want *CommandError", err)
	}
	if ce.Command != "getClient" || !ce.NotFound() || ce.AlreadyExists() {
		t.Errorf("CommandError %+v", ce)
	}
	if (&CommandError{Message: "Client already exists"}).AlreadyExists() != true {
		t.Error("AlreadyExists not detected")
	}
}

// TestExecuteParallel answers in random order, with responses for other
// clients and without correlationData in between (design 7.2: the plugin
// sends every response to every subscriber).
func TestExecuteParallel(t *testing.T) {
	var mu sync.Mutex
	var queued [][]map[string]any
	f := &fakeBroker{answer: func(req map[string]any) []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		queued = append(queued, []map[string]any{
			{"command": "listClients", "correlationData": "foreign-" + req["correlationData"].(string), "data": "foreign"},
			{"command": "getClient", "error": "Invalid correlationData data type."},
			{"command": req["command"], "correlationData": req["correlationData"], "data": req["username"]},
		})
		return nil
	}}
	c := newTest(t, f, 5*time.Second)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("client-%d", i)
			data, err := c.Execute(context.Background(), GetClient{Username: name})
			if err != nil {
				errs <- err
				return
			}
			if string(data) != `"`+name+`"` {
				errs <- fmt.Errorf("%s got %s", name, data)
			}
		}()
	}

	// Deliver once all requests are in, in random order.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		got := len(queued)
		mu.Unlock()
		if got == n {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d of %d requests published", got, n)
		case <-time.After(5 * time.Millisecond):
		}
	}
	mu.Lock()
	rand.Shuffle(len(queued), func(i, j int) { queued[i], queued[j] = queued[j], queued[i] })
	for _, rs := range queued {
		b, _ := json.Marshal(map[string]any{"responses": rs})
		c.HandleMessage(b)
	}
	mu.Unlock()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestExecuteTimeoutWithoutResponse(t *testing.T) {
	f := &fakeBroker{}
	c := newTest(t, f, 50*time.Millisecond)
	start := time.Now()
	_, err := c.Execute(context.Background(), GetClient{Username: "x"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %s", d)
	}
}

func TestExecutePublishNotConfirmed(t *testing.T) {
	f := &fakeBroker{block: true}
	c := newTest(t, f, 50*time.Millisecond)
	if _, err := c.Execute(context.Background(), GetClient{Username: "x"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("error %v, want ErrTimeout (state unknown)", err)
	}
}

func TestExecuteNotConnected(t *testing.T) {
	f := &fakeBroker{err: fmt.Errorf("%w: context deadline exceeded", mqttclient.ErrNotConnected)}
	c := newTest(t, f, time.Second)
	_, err := c.Execute(context.Background(), GetClient{Username: "x"})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTimeout) {
		t.Fatalf("error %v, want ErrUnavailable only", err)
	}
}

func TestExecuteOtherPublishError(t *testing.T) {
	f := &fakeBroker{err: &mqttclient.PubackError{ReasonCode: 0x87}}
	c := newTest(t, f, time.Second)
	_, err := c.Execute(context.Background(), GetClient{Username: "x"})
	var pe *mqttclient.PubackError
	if !errors.As(err, &pe) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTimeout) {
		t.Fatalf("error %v, want the PubackError", err)
	}
}

func TestExecuteCallerCancels(t *testing.T) {
	f := &fakeBroker{}
	c := newTest(t, f, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	_, err := c.Execute(ctx, GetClient{Username: "x"})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
		t.Fatalf("error %v, want context.Canceled", err)
	}
}

func TestLateResponseIsDropped(t *testing.T) {
	f := &fakeBroker{}
	c := newTest(t, f, 20*time.Millisecond)
	if _, err := c.Execute(context.Background(), GetClient{Username: "x"}); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	id := f.requests[0]["correlationData"].(string)
	b, _ := json.Marshal(map[string]any{"responses": []any{map[string]any{"command": "getClient", "correlationData": id}}})
	c.HandleMessage(b) // must neither block nor panic
}

func TestHandleMessageIgnoresGarbage(t *testing.T) {
	c := NewClient(&fakeBroker{}, time.Second, nil)
	for _, p := range []string{``, `not json`, `{"responses":"x"}`, `{"responses":[{"correlationData":5}]}`, `{}`} {
		c.HandleMessage([]byte(p))
	}
}

type badCommand struct {
	Command string `json:"command"`
}

func (badCommand) CommandName() string { return "bad" }

type listCommand []string

func (listCommand) CommandName() string { return "list" }

func TestEncodeRejectsReservedAndNonObject(t *testing.T) {
	if _, err := encode(badCommand{Command: "deleteClient"}, "id"); err == nil {
		t.Error("field command accepted")
	}
	if _, err := encode(listCommand{"a"}, "id"); err == nil {
		t.Error("non-object command accepted")
	}
}
