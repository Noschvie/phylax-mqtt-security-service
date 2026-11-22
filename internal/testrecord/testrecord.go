// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testrecord records HTTP exchanges of tests so that
// test/openapi/check.py can validate every response against
// api/openapi.yaml. It is used only by tests and does nothing unless
// PMSS_TEST_RECORD_DIR is set.
package testrecord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
)

// EnvDir names the directory for the records; one file per test process.
const EnvDir = "PMSS_TEST_RECORD_DIR"

// Exchange is one recorded response.
type Exchange struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"` // escaped path without query
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

var headers = []string{"Content-Type", "ETag", "Location", "Cache-Control", "WWW-Authenticate", "Allow"}

var (
	mu   sync.Mutex
	file *os.File
)

// Enabled reports whether records are written.
func Enabled() bool { return os.Getenv(EnvDir) != "" }

// Record appends one exchange.
func Record(method, path string, status int, h http.Header, body []byte) {
	dir := os.Getenv(EnvDir)
	if dir == "" {
		return
	}
	ex := Exchange{Method: method, Path: path, Status: status, Headers: map[string]string{}, Body: string(body)}
	for _, k := range headers {
		if v := h.Get(k); v != "" {
			ex.Headers[k] = v
		}
	}
	line, err := json.Marshal(ex)
	if err != nil {
		panic(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if file == nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%d.jsonl", os.Getpid())), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			panic(err)
		}
		file = f
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		panic(err)
	}
}

// Handler records every response of h.
func Handler(h http.Handler) http.Handler {
	if !Enabled() {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		Record(r.Method, r.URL.EscapedPath(), rec.Code, rec.Header(), rec.Body.Bytes())
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = bytes.NewReader(rec.Body.Bytes()).WriteTo(w)
	})
}
