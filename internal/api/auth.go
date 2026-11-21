// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

// require wraps h with the token check for scope (SEC-16).
func (s *server) require(scope auth.Scope, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2, p := s.opts.Auth.Authorize(r, scope)
		if p != nil {
			problem.Write(w, r, p)
			return
		}
		h.ServeHTTP(w, r2)
	})
}
