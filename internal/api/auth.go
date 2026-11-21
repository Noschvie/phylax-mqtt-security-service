// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

// Scope of a bearer token (specification 2.1). write does not include read.
type Scope string

const (
	ScopeRead  Scope = "read"
	ScopeWrite Scope = "write"
)

// Authorizer checks the bearer token of a request for a scope. It returns
// the request to continue with (e.g. with the caller in its context) or a
// problem: 401 invalid_token or 403 insufficient_scope, with
// WWW-Authenticate set (RFC 6750).
type Authorizer interface {
	Authorize(r *http.Request, scope Scope) (*http.Request, *problem.Problem)
}

// DenyAll rejects every request. It is the authorizer until the token
// check (Keycloak, go-oidc) is in place, so the API is closed by default.
type DenyAll struct{}

func (DenyAll) Authorize(*http.Request, Scope) (*http.Request, *problem.Problem) {
	return nil, &problem.Problem{
		Code:            problem.InvalidToken,
		Detail:          "Token verification is not configured.",
		WWWAuthenticate: `Bearer error="invalid_token", error_description="token verification is not configured"`,
	}
}

// require wraps h with the token check for scope.
func (s *server) require(scope Scope, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2, p := s.opts.Auth.Authorize(r, scope)
		if p != nil {
			problem.Write(w, r, p)
			return
		}
		h.ServeHTTP(w, r2)
	})
}
