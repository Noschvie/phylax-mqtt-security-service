// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

// Against the test realm of test/integration/keycloak (Keycloak 26.8.2):
//
//	PMSS_TEST_KEYCLOAK=http://127.0.0.1:8180 go test -run Keycloak -v ./internal/auth/

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

const (
	tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessType    = "urn:ietf:params:oauth:token-type:access_token"
)

func keycloakRealm(t *testing.T) string {
	base := os.Getenv("PMSS_TEST_KEYCLOAK")
	if base == "" {
		t.Skip("PMSS_TEST_KEYCLOAK not set (needs test/integration/keycloak)")
	}
	return strings.TrimRight(base, "/") + "/realms/pmss-test"
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func kcToken(t *testing.T, realm, client, secret string, form url.Values) tokenResponse {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr tokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&tr)
	if tr.AccessToken == "" {
		t.Fatalf("no token from %s: %d %s", client, resp.StatusCode, tr.Error)
	}
	return tr
}

func clientCredentials(t *testing.T, realm, client string) string {
	return kcToken(t, realm, client, client+"-secret", url.Values{"grant_type": {"client_credentials"}}).AccessToken
}

func userTokens(t *testing.T, realm, user string) tokenResponse {
	return kcToken(t, realm, "tasmofleet-test", "tasmofleet-test-secret", url.Values{
		"grant_type": {"password"}, "username": {user}, "password": {user}, "scope": {"openid"},
	})
}

func exchange(t *testing.T, realm, subject string) string {
	return kcToken(t, realm, "tasmofleet-test", "tasmofleet-test-secret", url.Values{
		"grant_type": {tokenExchange}, "subject_token": {subject}, "subject_token_type": {accessType},
		"requested_token_type": {accessType}, "audience": {audience}, "scope": {"read write"},
	}).AccessToken
}

// TestKeycloak runs the Authorizer of the service against real tokens.
func TestKeycloak(t *testing.T) {
	realm := keycloakRealm(t)
	v, err := NewVerifier(VerifierConfig{Issuer: realm, Audience: audience})
	if err != nil {
		t.Fatal(err)
	}
	b := &Bearer{Verifier: v}
	authorize := func(token string, scope Scope) (Caller, *problem.Problem) {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r2, p := b.Authorize(r, scope)
		if p != nil {
			return Caller{}, p
		}
		c, _ := CallerFrom(r2.Context())
		return c, nil
	}
	allowed := func(t *testing.T, token string, scope Scope) Caller {
		t.Helper()
		c, p := authorize(token, scope)
		if p != nil {
			t.Fatalf("%s refused: %s", scope, p)
		}
		return c
	}
	refused := func(t *testing.T, token string, scope Scope, code problem.Code) {
		t.Helper()
		if _, p := authorize(token, scope); p == nil || p.Code != code {
			t.Fatalf("%s: %v, want %s", scope, p, code)
		}
	}

	t.Run("msm-test-rw reads and writes", func(t *testing.T) {
		tok := clientCredentials(t, realm, "msm-test-rw")
		allowed(t, tok, ScopeRead)
		if c := allowed(t, tok, ScopeWrite); c.Azp != "msm-test-rw" || c.Subject == "" {
			t.Errorf("caller %+v", c)
		}
	})
	t.Run("msm-test-ro only reads", func(t *testing.T) {
		tok := clientCredentials(t, realm, "msm-test-ro")
		allowed(t, tok, ScopeRead)
		refused(t, tok, ScopeWrite, problem.InsufficientScope)
	})
	t.Run("service account without security-admin gets no write", func(t *testing.T) {
		refused(t, clientCredentials(t, realm, "msm-test-rw-norole"), ScopeWrite, problem.InsufficientScope)
	})
	t.Run("token exchange for alice: write, user in the audit", func(t *testing.T) {
		c := allowed(t, exchange(t, realm, userTokens(t, realm, "alice").AccessToken), ScopeWrite)
		if c.Username != "alice" || c.Azp != "tasmofleet-test" {
			t.Errorf("caller %+v", c)
		}
	})
	t.Run("token exchange for bob: read only", func(t *testing.T) {
		tok := exchange(t, realm, userTokens(t, realm, "bob").AccessToken)
		allowed(t, tok, ScopeRead)
		refused(t, tok, ScopeWrite, problem.InsufficientScope)
	})
	t.Run("original TasmoFleet, ID and refresh tokens are refused", func(t *testing.T) {
		tr := userTokens(t, realm, "alice")
		refused(t, tr.AccessToken, ScopeRead, problem.InvalidToken)
		if tr.IDToken != "" {
			refused(t, tr.IDToken, ScopeRead, problem.InvalidToken)
		}
		if tr.RefreshToken != "" {
			refused(t, tr.RefreshToken, ScopeRead, problem.InvalidToken)
		}
	})
}
