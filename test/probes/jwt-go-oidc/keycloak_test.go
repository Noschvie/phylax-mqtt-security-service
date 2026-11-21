// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtprobe

// Against the test realm of test/integration/keycloak (Keycloak 26.8.2):
//
//	PMSS_TEST_KEYCLOAK=http://127.0.0.1:8180 go test -run Keycloak -v ./...

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

const (
	tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessType    = "urn:ietf:params:oauth:token-type:access_token"
)

func keycloak(t *testing.T) string {
	base := os.Getenv("PMSS_TEST_KEYCLOAK")
	if base == "" {
		t.Skip("PMSS_TEST_KEYCLOAK not set (needs test/integration/keycloak)")
	}
	return strings.TrimRight(base, "/") + "/realms/pmss-test"
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
}

func token(t *testing.T, realm, client, secret string, form url.Values) tokenResponse {
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
	json.NewDecoder(resp.Body).Decode(&tr)
	if tr.AccessToken == "" {
		t.Fatalf("no token from %s: %d %s", client, resp.StatusCode, tr.Error)
	}
	return tr
}

func clientCredentials(t *testing.T, realm, client string) string {
	return token(t, realm, client, client+"-secret", url.Values{"grant_type": {"client_credentials"}}).AccessToken
}

// userTokens logs a test user in at tasmofleet-test (password grant, test realm only).
func userTokens(t *testing.T, realm, user string) tokenResponse {
	return token(t, realm, "tasmofleet-test", "tasmofleet-test-secret", url.Values{
		"grant_type": {"password"}, "username": {user}, "password": {user}, "scope": {"openid"},
	})
}

func exchange(t *testing.T, realm, subject, scope string) string {
	return token(t, realm, "tasmofleet-test", "tasmofleet-test-secret", url.Values{
		"grant_type": {tokenExchange}, "subject_token": {subject}, "subject_token_type": {accessType},
		"requested_token_type": {accessType}, "audience": {audience}, "scope": {scope},
	}).AccessToken
}

func TestKeycloak(t *testing.T) {
	realm := keycloak(t)
	ctx := context.Background()
	v, err := New(ctx, Config{Issuer: realm, Audience: audience})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("service account msm-test-rw: read and write", func(t *testing.T) {
		c, err := v.Verify(ctx, clientCredentials(t, realm, "msm-test-rw"))
		if err != nil {
			t.Fatal(err)
		}
		if !c.HasScope("read") || !c.HasScope("write") || c.Azp != "msm-test-rw" {
			t.Errorf("claims = %+v", c)
		}
	})

	t.Run("service account msm-test-ro: read only", func(t *testing.T) {
		c, err := v.Verify(ctx, clientCredentials(t, realm, "msm-test-ro"))
		if err != nil {
			t.Fatal(err)
		}
		if !c.HasScope("read") || c.HasScope("write") {
			t.Errorf("scopes = %v", c.Scopes)
		}
	})

	t.Run("token exchange for alice: user in the token", func(t *testing.T) {
		c, err := v.Verify(ctx, exchange(t, realm, userTokens(t, realm, "alice").AccessToken, "read write"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Username != "alice" || !c.HasScope("write") || c.Azp != "tasmofleet-test" {
			t.Errorf("claims = %+v", c)
		}
	})

	t.Run("token exchange for bob: no write", func(t *testing.T) {
		c, err := v.Verify(ctx, exchange(t, realm, userTokens(t, realm, "bob").AccessToken, "read write"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Username != "bob" || c.HasScope("write") {
			t.Errorf("claims = %+v", c)
		}
	})

	t.Run("original TasmoFleet token rejected (aud)", func(t *testing.T) {
		if c, err := v.Verify(ctx, userTokens(t, realm, "alice").AccessToken); err == nil {
			t.Fatalf("accepted: %+v", c)
		} else {
			t.Logf("rejected: %v", err)
		}
	})

	t.Run("ID token rejected", func(t *testing.T) {
		id := userTokens(t, realm, "alice").IDToken
		if id == "" {
			t.Skip("no ID token")
		}
		if c, err := v.Verify(ctx, id); err == nil {
			t.Fatalf("accepted: %+v", c)
		} else {
			t.Logf("rejected: %v", err)
		}
	})

	t.Run("wrong audience configured", func(t *testing.T) {
		w, err := New(ctx, Config{Issuer: realm, Audience: "some-other-service"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Verify(ctx, clientCredentials(t, realm, "msm-test-rw")); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("refresh token rejected", func(t *testing.T) {
		// A Keycloak refresh token is signed with HS512 (realm secret): the
		// algorithm check already refuses it.
		form := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"alice"}}
		req, _ := http.NewRequest(http.MethodPost, realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("tasmofleet-test", "tasmofleet-test-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		if body.RefreshToken == "" {
			t.Skip("no refresh token")
		}
		_, err = v.Verify(ctx, body.RefreshToken)
		if err == nil {
			t.Fatal("accepted")
		}
		if errors.Is(err, ErrNotAccessToken) {
			t.Log("rejected by the typ check")
		} else {
			t.Logf("rejected: %v", err)
		}
	})
}
