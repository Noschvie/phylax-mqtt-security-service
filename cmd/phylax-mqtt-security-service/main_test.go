// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/api"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
)

func noenv(string) string { return "" }

func TestHealthURL(t *testing.T) {
	for in, want := range map[string]string{
		":8080":          "http://127.0.0.1:8080/healthz",
		"0.0.0.0:8080":   "http://127.0.0.1:8080/healthz",
		"[::]:8080":      "http://127.0.0.1:8080/healthz",
		"127.0.0.1:9000": "http://127.0.0.1:9000/healthz",
		"[::1]:9000":     "http://[::1]:9000/healthz",
	} {
		if got := healthURL(in); got != want {
			t.Errorf("healthURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunVersionAndUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, noenv, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Errorf("version: code %d, output %q", code, out.String())
	}
	if code := run([]string{"bogus"}, noenv, &out, &errOut); code != 2 {
		t.Errorf("unknown command: code %d, want 2", code)
	}
	if code := run([]string{"version", "extra"}, noenv, &out, &errOut); code != 2 {
		t.Errorf("too many arguments: code %d, want 2", code)
	}
}

func TestRunInvalidConfig(t *testing.T) {
	var out bytes.Buffer
	getenv := func(k string) string {
		if k == config.EnvLogLevel {
			return "verbose"
		}
		return ""
	}
	if code := run(nil, getenv, &out, io.Discard); code != 1 {
		t.Errorf("code %d, want 1", code)
	}
	if !strings.Contains(out.String(), "invalid configuration") {
		t.Errorf("no JSON error record: %q", out.String())
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(api.NewHandler(api.Options{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}))
	defer ok.Close()
	if err := healthcheck(ok.URL+"/healthz", time.Second); err != nil {
		t.Errorf("healthy service: %v", err)
	}
	if err := healthcheck(ok.URL+"/missing", time.Second); err == nil {
		t.Error("404 accepted as healthy")
	}
	ok.Close()
	if err := healthcheck(ok.URL+"/healthz", time.Second); err == nil {
		t.Error("stopped service accepted as healthy")
	}
}

// TestRunServerGracefulShutdown starts the server, lets a slow request run
// into the shutdown and checks that it still completes.
func TestRunServerGracefulShutdown(t *testing.T) {
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	})

	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := api.NewServer(cfg, mux, logger)

	// Bind first to learn the port, then hand the address to runServer.
	probe := httptest.NewUnstartedServer(nil)
	addr := probe.Listener.Addr().String()
	probe.Listener.Close()
	srv.Addr = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServer(ctx, srv, 5*time.Second, logger) }()

	var resp *http.Response
	var err error
	respc := make(chan struct{})
	go func() {
		defer close(respc)
		for i := 0; i < 50; i++ {
			resp, err = http.Get("http://" + addr + "/slow")
			if err == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the server")
	}
	cancel()

	<-respc
	if err != nil {
		t.Fatalf("request during shutdown: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "done" {
		t.Errorf("body %q, want done", body)
	}
	if err := <-done; err != nil {
		t.Errorf("runServer: %v", err)
	}
}

func TestParseBrokerVersion(t *testing.T) {
	for in, want := range map[string]string{
		"mosquitto version 2.1.2":    "2.1.2",
		"mosquitto version 2.0.18\n": "2.0.18",
		"2.1.2":                      "2.1.2",
		"":                           "",
	} {
		if got := parseBrokerVersion(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestNewAuthorizer(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := config.Default().OIDC
	a, err := newAuthorizer(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.(auth.DenyAll); !ok {
		t.Errorf("without issuer: %T, want auth.DenyAll", a)
	}
	cfg.Issuer = "https://kc.example.org/realms/pmss"
	a, err = newAuthorizer(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := a.(*auth.Bearer)
	if !ok || b.ScopeNames[auth.ScopeRead] != "read" || b.ScopeNames[auth.ScopeWrite] != "write" {
		t.Errorf("with issuer: %T %+v", a, a)
	}
}
