// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth checks the bearer tokens of the REST API (design 7.5,
// decisions T-1 and T-7, SEC-15, SEC-16): only access tokens issued by
// Keycloak, signature, iss, aud, exp/nbf and algorithm checked by go-oidc,
// token type and scopes checked here. The service checks scopes only, never
// roles; Keycloak issues write only to security-admin.
package auth

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

// Scope required by an endpoint (specification 2.1). write does not
// include read.
type Scope string

const (
	ScopeRead  Scope = "read"
	ScopeWrite Scope = "write"
)

// Authorizer checks the bearer token of a request for a scope. It returns
// the request to continue with (the caller in its context) or a problem:
// 401 invalid_token or 403 insufficient_scope, with WWW-Authenticate set
// (RFC 6750).
type Authorizer interface {
	Authorize(r *http.Request, scope Scope) (*http.Request, *problem.Problem)
}

// Realm in WWW-Authenticate.
const Realm = "phylax-mqtt-security-service"

// DenyAll rejects every request. It is used while no issuer is configured,
// so the API is closed by default.
type DenyAll struct{}

func (DenyAll) Authorize(*http.Request, Scope) (*http.Request, *problem.Problem) {
	return nil, &problem.Problem{
		Code:            problem.InvalidToken,
		Detail:          "Token verification is not configured.",
		WWWAuthenticate: `Bearer realm="` + Realm + `", error="invalid_token", error_description="token verification is not configured"`,
	}
}

// Caller is the identity from a verified token, for the audit log
// (design 7.5): never the token itself.
type Caller struct {
	Subject  string   // sub
	Username string   // preferred_username
	Azp      string   // client the token was issued to
	Scopes   []string // from the scope claim
}

// HasScope reports whether the token carries the scope name.
func (c Caller) HasScope(name string) bool { return slices.Contains(c.Scopes, name) }

// LogValue keeps the scopes and identity readable in slog records.
func (c Caller) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("sub", c.Subject),
		slog.String("username", c.Username),
		slog.String("azp", c.Azp),
	)
}

type callerKey struct{}

// WithCaller returns ctx carrying c.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller of a request that passed the token check.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// TokenVerifier verifies a raw access token.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (Caller, error)
}

// Bearer is the Authorizer for Keycloak access tokens.
type Bearer struct {
	Verifier TokenVerifier
	// ScopeNames maps the scopes of the API to the names in the token;
	// default read and write.
	ScopeNames map[Scope]string
	Logger     *slog.Logger
}

// Authorize implements Authorizer.
func (b *Bearer) Authorize(r *http.Request, scope Scope) (*http.Request, *problem.Problem) {
	logger := b.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	raw, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok {
		// RFC 6750 3.1: no error attribute when no credentials were sent.
		return nil, &problem.Problem{
			Code:            problem.InvalidToken,
			Detail:          "Bearer token required.",
			WWWAuthenticate: `Bearer realm="` + Realm + `"`,
		}
	}
	caller, err := b.Verifier.Verify(r.Context(), raw)
	if err != nil {
		// The reason is logged, not returned: it helps an attacker more
		// than a legitimate client. The token is never logged.
		logger.Info("token rejected", "path", r.URL.Path, "reason", err.Error())
		return nil, &problem.Problem{
			Code:            problem.InvalidToken,
			Detail:          "The bearer token is invalid or expired.",
			WWWAuthenticate: `Bearer realm="` + Realm + `", error="invalid_token"`,
		}
	}
	name := b.scopeName(scope)
	if !caller.HasScope(name) {
		logger.Info("scope missing", "path", r.URL.Path, "caller", caller, "scope", name)
		return nil, &problem.Problem{
			Code:            problem.InsufficientScope,
			Detail:          "The token lacks scope '" + name + "'.",
			WWWAuthenticate: `Bearer realm="` + Realm + `", error="insufficient_scope", scope="` + name + `"`,
		}
	}
	return r.WithContext(WithCaller(r.Context(), caller)), nil
}

func (b *Bearer) scopeName(s Scope) string {
	if n, ok := b.ScopeNames[s]; ok && n != "" {
		return n
	}
	return string(s)
}

// bearerToken returns the token of exactly one "Authorization: Bearer …"
// header (RFC 6750 2.1; the scheme is case-insensitive).
func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
