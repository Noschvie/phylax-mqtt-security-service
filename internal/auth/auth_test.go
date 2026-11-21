// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

type fakeVerifier map[string]Caller // token → caller

func (f fakeVerifier) Verify(_ context.Context, raw string) (Caller, error) {
	if c, ok := f[raw]; ok {
		return c, nil
	}
	return Caller{}, errors.New("signature invalid")
}

func TestBearerToken(t *testing.T) {
	for _, tc := range []struct {
		values []string
		token  string
		ok     bool
	}{
		{[]string{"Bearer abc.def.ghi"}, "abc.def.ghi", true},
		{[]string{"bearer abc"}, "abc", true},
		{[]string{"BEARER  abc "}, "abc", true},
		{nil, "", false},
		{[]string{"Bearer"}, "", false},
		{[]string{"Bearer "}, "", false},
		{[]string{"Basic dXNlcjpwYXNz"}, "", false},
		{[]string{"Bearer a b"}, "", false},
		{[]string{"Bearer a", "Bearer b"}, "", false},
	} {
		token, ok := bearerToken(tc.values)
		if token != tc.token || ok != tc.ok {
			t.Errorf("%q: got %q %v, want %q %v", tc.values, token, ok, tc.token, tc.ok)
		}
	}
}

func TestBearerAuthorize(t *testing.T) {
	var logs bytes.Buffer
	b := &Bearer{
		Verifier: fakeVerifier{
			"rw":   {Subject: "alice", Username: "alice", Scopes: []string{"read", "write"}},
			"ro":   {Subject: "bob", Scopes: []string{"read"}},
			"wo":   {Subject: "svc", Scopes: []string{"write"}},
			"name": {Subject: "carol", Scopes: []string{"pmss.read"}},
		},
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	req := func(auth string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		return r
	}

	r, p := b.Authorize(req("Bearer rw"), ScopeWrite)
	if p != nil {
		t.Fatalf("rw/write: %v", p)
	}
	if c, ok := CallerFrom(r.Context()); !ok || c.Subject != "alice" {
		t.Errorf("caller %+v %v", c, ok)
	}

	for _, tc := range []struct {
		auth   string
		scope  Scope
		code   problem.Code
		header string
	}{
		{"", ScopeRead, problem.InvalidToken, `Bearer realm="phylax-mqtt-security-service"`},
		{"Basic x", ScopeRead, problem.InvalidToken, `Bearer realm="phylax-mqtt-security-service"`},
		{"Bearer forged", ScopeRead, problem.InvalidToken, `Bearer realm="phylax-mqtt-security-service", error="invalid_token"`},
		{"Bearer ro", ScopeWrite, problem.InsufficientScope, `Bearer realm="phylax-mqtt-security-service", error="insufficient_scope", scope="write"`},
		// write does not include read (specification 2.1).
		{"Bearer wo", ScopeRead, problem.InsufficientScope, `Bearer realm="phylax-mqtt-security-service", error="insufficient_scope", scope="read"`},
	} {
		_, p := b.Authorize(req(tc.auth), tc.scope)
		if p == nil || p.Code != tc.code || p.WWWAuthenticate != tc.header {
			t.Errorf("%q/%s: %+v, want %s with %s", tc.auth, tc.scope, p, tc.code, tc.header)
		}
	}
	if strings.Contains(logs.String(), "forged") {
		t.Error("token in the log")
	}

	// Configured scope names.
	b.ScopeNames = map[Scope]string{ScopeRead: "pmss.read", ScopeWrite: "pmss.write"}
	if _, p := b.Authorize(req("Bearer name"), ScopeRead); p != nil {
		t.Errorf("pmss.read: %v", p)
	}
	if _, p := b.Authorize(req("Bearer ro"), ScopeRead); p == nil {
		t.Error("read accepted although the scope is called pmss.read")
	}
}

func TestDenyAll(t *testing.T) {
	_, p := DenyAll{}.Authorize(httptest.NewRequest(http.MethodGet, "/", nil), ScopeRead)
	if p == nil || p.Code != problem.InvalidToken || !strings.HasPrefix(p.WWWAuthenticate, "Bearer ") {
		t.Errorf("%+v", p)
	}
}
