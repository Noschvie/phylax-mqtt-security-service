// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit writes one record per changing request (design 7.6, A-6,
// SEC-10, SEC-32): who (from the token), what, which object, result, and
// the object before and after. Records carry "log_type":"audit" and go to
// stdout with the other logs. Passwords, password hashes and tokens are
// never part of them; the API objects contain none.
package audit

import (
	"context"
	"log/slog"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
)

// Results of a change.
const (
	ResultSuccess = "success"
	ResultFailed  = "failed"  // nothing was changed (validation, 4xx, 503)
	ResultUnknown = "unknown" // no answer from the broker; may have been applied (504, S-13)
	ResultPartial = "partial" // compensation failed (502 partial_failure)
)

// Event is one audited request.
type Event struct {
	Action string // e.g. createClient, setClientPassword, replaceACLs
	Kind   string // client, group or role
	Name   string // object in the path or body
	Result string
	Code   string // problem code for anything but success
	Detail string
	Before any // object before the change; nil if it did not exist or was not read
	After  any // object after the change; nil if deleted or unknown
}

// Logger writes audit records.
type Logger struct {
	l *slog.Logger
}

// New returns an audit logger on top of l.
func New(l *slog.Logger) *Logger {
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return &Logger{l: l}
}

// Record writes e with the caller from ctx.
func (a *Logger) Record(ctx context.Context, e Event) {
	attrs := []slog.Attr{
		slog.String("log_type", "audit"),
		slog.String("action", e.Action),
		slog.String("kind", e.Kind),
		slog.String("name", e.Name),
		slog.String("result", e.Result),
	}
	if c, ok := auth.CallerFrom(ctx); ok {
		attrs = append(attrs, slog.Any("caller", c))
	}
	if e.Code != "" {
		attrs = append(attrs, slog.String("code", e.Code))
	}
	if e.Detail != "" {
		attrs = append(attrs, slog.String("detail", e.Detail))
	}
	if e.Before != nil {
		attrs = append(attrs, slog.Any("before", e.Before))
	}
	if e.After != nil {
		attrs = append(attrs, slog.Any("after", e.After))
	}
	level := slog.LevelInfo
	if e.Result != ResultSuccess {
		level = slog.LevelWarn
	}
	a.l.LogAttrs(ctx, level, "audit", attrs...)
}
