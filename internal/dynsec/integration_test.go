// SPDX-License-Identifier: AGPL-3.0-or-later

package dynsec_test

// Integration tests against Mosquitto with Dynamic Security, see
// test/integration/broker. They run only if PMSS_TEST_BROKER_URL is set:
//
//	PMSS_TEST_BROKER_URL     e.g. mqtts://127.0.0.1:18884
//	PMSS_TEST_BROKER_CERTS   directory created by make-certs.sh (…/run/certs)
//	PMSS_TEST_BROKER_SERVER_NAME  SAN to check, default mosquitto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/mqttclient"
)

type broker struct {
	url        *url.URL
	certs      string
	serverName string
}

func testBroker(t *testing.T) broker {
	t.Helper()
	raw := os.Getenv("PMSS_TEST_BROKER_URL")
	if raw == "" {
		t.Skip("PMSS_TEST_BROKER_URL not set; see test/integration/broker")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("PMSS_TEST_BROKER_URL: %v", err)
	}
	b := broker{url: u, certs: os.Getenv("PMSS_TEST_BROKER_CERTS"), serverName: os.Getenv("PMSS_TEST_BROKER_SERVER_NAME")}
	if b.certs == "" {
		t.Fatal("PMSS_TEST_BROKER_CERTS not set")
	}
	if b.serverName == "" {
		b.serverName = "mosquitto"
	}
	return b
}

func testLogger(t *testing.T) *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("test", t.Name())
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// connect opens a connection with the client certificate name (…/name.crt)
// to addr and returns the DynSec client. waitReady: fail unless the
// response topic is subscribed within 10 s.
func connect(t *testing.T, b broker, name, addr string, waitReady bool) (*mqttclient.Conn, *dynsec.Client) {
	t.Helper()
	tlsCfg, id, err := mqttclient.LoadTLS(filepath.Join(b.certs, "server-ca.crt"),
		filepath.Join(b.certs, name+".crt"), filepath.Join(b.certs, name+".key"), b.serverName)
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" {
		addr = b.url.Host
	}
	logger := testLogger(t).With("identity", id.CommonName)
	conn := mqttclient.New(mqttclient.Options{
		BrokerURL:      &url.URL{Scheme: "mqtts", Host: addr},
		TLS:            tlsCfg,
		KeepAlive:      30 * time.Second,
		ResponseTopic:  dynsec.ResponseTopic,
		Logger:         logger,
		ConnectTimeout: 2 * time.Second,
		Backoff:        func(int) time.Duration { return 100 * time.Millisecond },
	})
	client := dynsec.NewClient(conn, 5*time.Second, logger)
	ctx, cancel := context.WithCancel(context.Background())
	if err := conn.Start(ctx, client.HandleMessage); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = conn.Close(closeCtx)
		cancel()
	})
	if waitReady {
		waitFor(t, 10*time.Second, conn.Ready, "connection ready")
	}
	return conn, client
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Changing commands, only for these tests; the service gets its own with
// the write endpoints.
type createClient struct {
	Username        string `json:"username"`
	Textdescription string `json:"textdescription,omitempty"`
}

func (createClient) CommandName() string { return "createClient" }

type deleteClient struct {
	Username string `json:"username"`
}

func (deleteClient) CommandName() string { return "deleteClient" }

func randomName(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

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
	p := newProxy(t, b.url.Host)
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
	p := newProxy(t, b.url.Host)
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
