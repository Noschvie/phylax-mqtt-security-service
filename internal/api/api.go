// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api holds the HTTP server and the handlers of the REST API
// (interface specification "MQTT Security Service API v1", design 7.3).
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/model"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

// APIVersion is the version of the specification implemented here.
const APIVersion = "1.0"

// ImplementationName is reported in GET /api/v1/info.
const ImplementationName = "phylax-mqtt-security-service"

// Executor runs DynSec commands; *dynsec.Client implements it.
type Executor interface {
	Execute(ctx context.Context, cmd dynsec.Command) (json.RawMessage, error)
}

// Options of the handler.
type Options struct {
	Logger *slog.Logger
	// Version of this build, reported in GET /api/v1/info.
	Version string
	// Managed marks and the body limit come from the configuration.
	Managed         config.Managed
	MaxRequestBytes int64
	// DynSec executes the commands; required for the /api/v1 endpoints.
	DynSec Executor
	// Auth checks the bearer token; nil denies every /api/v1 request.
	Auth auth.Authorizer
	// BrokerVersion returns the version from $SYS/broker/version, "" if
	// not known yet.
	BrokerVersion func() string
	// Now is the clock for exportedAt; default time.Now.
	Now func() time.Time
}

type server struct {
	opts   Options
	marks  model.Marks
	routes *http.ServeMux
}

// NewHandler returns all routes, wrapped in access log and body limit.
// Unknown paths and methods are answered as problem+json too.
func NewHandler(opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Auth == nil {
		opts.Auth = auth.DenyAll{}
	}
	if opts.MaxRequestBytes < config.MinRequestBytes {
		opts.MaxRequestBytes = config.MinRequestBytes
	}
	if opts.BrokerVersion == nil {
		opts.BrokerVersion = func() string { return "" }
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &server{opts: opts, marks: model.Marks(opts.Managed), routes: http.NewServeMux()}

	// Container health check: internal, no token, no version in the path,
	// no sensitive information (design 7.3, S-9).
	s.routes.HandleFunc("GET /healthz", handleHealthz)

	read := func(pattern string, h http.HandlerFunc) {
		s.routes.Handle(pattern, s.require(auth.ScopeRead, h))
	}
	read("GET /api/v1/info", s.handleInfo)
	read("GET /api/v1/export", s.handleExport)
	read("GET /api/v1/clients", s.handleListClients)
	read("GET /api/v1/clients/{username}", s.handleGetClient)
	read("GET /api/v1/groups", s.handleListGroups)
	read("GET /api/v1/groups/{group}", s.handleGetGroup)
	read("GET /api/v1/roles", s.handleListRoles)
	read("GET /api/v1/roles/{role}", s.handleGetRole)

	return accessLog(opts.Logger, s.limitBody(http.HandlerFunc(s.route)))
}

// route dispatches to the registered patterns and answers everything else
// with 404 not_found or 405 method_not_allowed as problem+json.
func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if _, pattern := s.routes.Handler(r); pattern != "" {
		// ServeHTTP, not the returned handler: only it sets the path values.
		s.routes.ServeHTTP(w, r)
		return
	}
	var allowed []string
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pattern := s.routes.Handler(probe); pattern != "" {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		problem.Write(w, r, problem.New(problem.MethodNotAllowed, r.Method+" is not allowed here"))
		return
	}
	problem.Write(w, r, problem.New(problem.NotFound, "No such endpoint"))
}

// limitBody rejects bodies above the limit (S-11). Bodies with a known
// length are refused before they are read; others are cut by
// http.MaxBytesReader, which decodeJSON maps to 413.
func (s *server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > s.opts.MaxRequestBytes {
			problem.Write(w, r, problem.New(problem.PayloadTooLarge, "Request body exceeds limits.maxRequestBytes"))
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxRequestBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// NewServer returns the HTTP server with the timeouts from the
// configuration (design 7.3). Errors of the server itself go to the
// structured log.
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
