// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api holds the HTTP server and the handlers of the REST API.
// So far it only serves the health check; the endpoints of the interface
// specification "MQTT Security Service API v1" follow.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
)

// NewHandler returns the routes of the service, wrapped in the access log.
func NewHandler(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	// Container health check: internal, no token, no version in the path,
	// no sensitive information (design section 7.3, S-9).
	mux.HandleFunc("GET /healthz", handleHealthz)
	return accessLog(logger, mux)
}

// NewServer returns the HTTP server with the timeouts from the
// configuration (design section 7.3). Errors of the server itself go to
// the structured log.
func NewServer(cfg config.Config, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// statusRecorder remembers the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the original writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// accessLog writes one record per request: method, path, status and
// duration. Never headers or bodies, so no token or password ends up in the
// log (SEC-10). Health checks are logged at debug level only.
func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		level := slog.LevelInfo
		if r.URL.Path == "/healthz" {
			level = slog.LevelDebug
		}
		logger.LogAttrs(r.Context(), level, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
		)
	})
}
