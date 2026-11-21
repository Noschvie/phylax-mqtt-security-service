// SPDX-License-Identifier: AGPL-3.0-or-later

package dynsec_test

// Integration tests against Mosquitto with Dynamic Security, see
// test/integration/broker and package testbroker.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/mqttclient"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/testbroker"
)

// connect opens a connection with the client certificate name to addr
// ("" = the broker itself).
func connect(t *testing.T, b testbroker.Broker, name, addr string, waitReady bool) (*mqttclient.Conn, *dynsec.Client) {
	t.Helper()
	return testbroker.Connect(t, b, testbroker.Options{Cert: name, Addr: addr, WaitReady: waitReady})
}

var (
	testBroker = testbroker.FromEnv
	waitFor    = testbroker.WaitFor
	randomName = testbroker.RandomName
)

type createClient = testbroker.CreateClient
type deleteClient = testbroker.DeleteClient

type clientData struct {
	Client map[string]json.RawMessage `json:"client"`
}

func username(t *testing.T, data json.RawMessage) string {
	t.Helper()
	var d clientData
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("getClient data %s: %v", data, err)
	}
	var name string
	_ = json.Unmarshal(d.Client["username"], &name)
	return name
}

func TestIntegrationCommands(t *testing.T) {
	b := testBroker(t)
	_, c := connect(t, b, "pmss-admin", "", true)
	ctx := context.Background()

	data, err := c.Execute(ctx, dynsec.ListClients{})
	if err != nil {
		t.Fatalf("listClients: %v", err)
	}
	if !strings.Contains(string(data), `"pmss-admin"`) {
		t.Errorf("listClients without pmss-admin: %s", data)
	}

	_, err = c.Execute(ctx, dynsec.GetClient{Username: randomName("missing-")})
	var ce *dynsec.CommandError
	if !errors.As(err, &ce) || !ce.NotFound() {
		t.Fatalf("getClient of a missing client: %v, want CommandError not found", err)
	}

	name := randomName("pmss-it-")
	if _, err := c.Execute(ctx, createClient{Username: name, Textdescription: "managed-by: pmss"}); err != nil {
		t.Fatalf("createClient: %v", err)
	}
	t.Cleanup(func() { _, _ = c.Execute(context.Background(), deleteClient{Username: name}) })

	_, err = c.Execute(ctx, createClient{Username: name})
	if !errors.As(err, &ce) || !ce.AlreadyExists() {
		t.Errorf("second createClient: %v, want CommandError already exists", err)
	}

	data, err = c.Execute(ctx, dynsec.GetClient{Username: name})
	if err != nil {
		t.Fatalf("getClient: %v", err)
	}
	if got := username(t, data); got != name {
		t.Errorf("getClient returned %q, want %q", got, name)
	}
	for _, field := range []string{"password", "encoded_password", "salt", "iterations"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Errorf("getClient returns %q (S-5 expects no hash): %s", field, data)
		}
	}

	if _, err := c.Execute(ctx, deleteClient{Username: name}); err != nil {
		t.Fatalf("deleteClient: %v", err)
	}
	if _, err := c.Execute(ctx, dynsec.GetClient{Username: name}); !errors.As(err, &ce) || !ce.NotFound() {
		t.Errorf("getClient after delete: %v", err)
	}
}

// TestIntegrationParallelTwoAdmins: both admins subscribe to the same
// response topic and get each other's responses (design 7.2); each must
// still receive exactly its own answers.
func TestIntegrationParallelTwoAdmins(t *testing.T) {
	b := testBroker(t)
	_, svc := connect(t, b, "pmss-admin", "", true)
	_, bg := connect(t, b, "pmss-breakglass-admin", "", true)

	var wg sync.WaitGroup
	errs := make(chan error, 80)
	for i := range 40 {
		for _, c := range []*dynsec.Client{svc, bg} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				want := "pmss-admin"
				if i%2 == 1 {
					want = "pmss-breakglass-admin"
				}
				data, err := c.Execute(context.Background(), dynsec.GetClient{Username: want})
				if err != nil {
					errs <- err
					return
				}
				var d clientData
				_ = json.Unmarshal(data, &d)
				if got := strings.Trim(string(d.Client["username"]), `"`); got != want {
					errs <- fmt.Errorf("asked for %s, got %s", want, got)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestIntegrationReconnect cuts the TCP connection without DISCONNECT. After
// the reconnect the response topic must be subscribed again (autopaho does
// not do it by itself, design 7.2) and commands work.
func TestIntegrationReconnect(t *testing.T) {
	b := testBroker(t)
	p := newProxy(t, b.URL.Host)
	conn, c := connect(t, b, "pmss-admin", p.addr(), true)

	if _, err := c.Execute(context.Background(), dynsec.ListClients{}); err != nil {
		t.Fatalf("before the cut: %v", err)
	}

	p.cut()
	waitFor(t, 5*time.Second, func() bool { return !conn.Ready() }, "connection loss detected")

	// Execute waits for the new connection within its timeout.
	if _, err := c.Execute(context.Background(), dynsec.ListClients{}); err != nil {
		t.Fatalf("after the reconnect: %v", err)
	}
	if p.connections() < 2 {
		t.Errorf("%d connections through the proxy, want a reconnect", p.connections())
	}
}

// TestIntegrationBrokerDown: the proxy refuses connections; Execute ends
// with ErrUnavailable and does not send the command later.
func TestIntegrationBrokerDown(t *testing.T) {
	b := testBroker(t)
	p := newProxy(t, b.URL.Host)
	p.refuse(true)
	_, c := connect(t, b, "pmss-admin", p.addr(), false)

	name := randomName("pmss-down-")
	start := time.Now()
	_, err := c.Execute(context.Background(), createClient{Username: name})
	if !errors.Is(err, dynsec.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
	if d := time.Since(start); d < 4*time.Second || d > 8*time.Second {
		t.Errorf("returned after %s, want about the command timeout (5s)", d)
	}

	// Broker reachable again: the command must not appear afterwards.
	_, direct := connect(t, b, "pmss-breakglass-admin", "", true)
	p.refuse(false)
	time.Sleep(time.Second)
	var ce *dynsec.CommandError
	if _, err := direct.Execute(context.Background(), dynsec.GetClient{Username: name}); !errors.As(err, &ce) || !ce.NotFound() {
		t.Errorf("client %s exists after ErrUnavailable: %v", name, err)
		_, _ = direct.Execute(context.Background(), deleteClient{Username: name})
	}
}

// TestIntegrationWrongCA: a certificate of the server CA is rejected at the
// admin listener (design 5.2); the service never gets ready.
func TestIntegrationWrongCA(t *testing.T) {
	b := testBroker(t)
	conn, c := connect(t, b, "wrong-ca-client", "", false)
	time.Sleep(time.Second)
	if conn.Ready() {
		t.Fatal("connection with a certificate of the server CA is ready")
	}
	if _, err := c.Execute(context.Background(), dynsec.ListClients{}); !errors.Is(err, dynsec.ErrUnavailable) {
		t.Errorf("error %v, want ErrUnavailable", err)
	}
}

// proxy forwards TCP to the broker and can cut all connections.
type proxy struct {
	ln     net.Listener
	target string

	mu       sync.Mutex
	conns    []net.Conn
	count    int
	refusing bool
}

func newProxy(t *testing.T, target string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, target: target}
	go p.serve()
	t.Cleanup(func() { ln.Close(); p.cut() })
	return p
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) serve() {
	for {
		in, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		refusing := p.refusing
		p.mu.Unlock()
		if refusing {
			in.Close()
			continue
		}
		out, err := net.Dial("tcp", p.target)
		if err != nil {
			in.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, in, out)
		p.count++
		p.mu.Unlock()
		go func() { _, _ = io.Copy(out, in); out.Close() }()
		go func() { _, _ = io.Copy(in, out); in.Close() }()
	}
}

func (p *proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

func (p *proxy) refuse(on bool) {
	p.mu.Lock()
	p.refusing = on
	p.mu.Unlock()
}

func (p *proxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}
