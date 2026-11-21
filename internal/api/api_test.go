// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
)

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(Options{Logger: discard()}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if len(body) != 1 || body["status"] != "ok" {
		t.Errorf("body %v, want only status ok", body)
	}
}

func TestRouting(t *testing.T) {
	h := NewHandler(Options{Logger: discard()})
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodHead, "/healthz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, "/api/v1/healthz", http.StatusNotFound},
		{http.MethodGet, "/api/export", http.StatusNotFound}, // old path without version
		{http.MethodDelete, "/api/v1/export", http.StatusMethodNotAllowed},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(Options{Logger: logger})

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	h.ServeHTTP(httptest.NewRecorder(), req)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log is not JSON: %v\n%s", err, buf.String())
	}
	if rec["method"] != "GET" || rec["path"] != "/missing" || rec["status"] != float64(404) || rec["level"] != "INFO" {
		t.Errorf("unexpected record %v", rec)
	}
	if strings.Contains(buf.String(), "secret-token") {
		t.Error("access log contains the Authorization header")
	}

	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !strings.Contains(buf.String(), `"level":"DEBUG"`) {
		t.Errorf("health check not logged at debug: %s", buf.String())
	}
}

func TestNewServerTimeouts(t *testing.T) {
	cfg := config.Default()
	srv := NewServer(cfg, http.NotFoundHandler(), discard())
	if srv.Addr != cfg.ListenAddr ||
		srv.ReadHeaderTimeout != cfg.ReadHeaderTimeout ||
		srv.ReadTimeout != cfg.ReadTimeout ||
		srv.WriteTimeout != cfg.WriteTimeout ||
		srv.IdleTimeout != cfg.IdleTimeout {
		t.Errorf("server does not use the configuration: %+v", srv)
	}
	if srv.ErrorLog == nil {
		t.Error("ErrorLog not set")
	}
}
