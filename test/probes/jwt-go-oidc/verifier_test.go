// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

const audience = "phylax-mqtt-security-service"

// issuer is a minimal OIDC provider: discovery document and JWKS.
type issuer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	keys    []jose.JSONWebKey // published public keys
	fetches atomic.Int32      // JWKS requests
}

func newIssuer(t *testing.T) *issuer {
	is := &issuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                is.srv.URL,
			"jwks_uri":                              is.srv.URL + "/jwks",
			"authorization_endpoint":                is.srv.URL + "/auth",
			"token_endpoint":                        is.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		is.fetches.Add(1)
		is.mu.Lock()
		defer is.mu.Unlock()
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: is.keys})
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) publish(k signingKey) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.keys = append(is.keys, jose.JSONWebKey{Key: k.public, KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
}

type signingKey struct {
	kid     string
	alg     jose.SignatureAlgorithm
	private any
	public  any
}

func rsaKey(t *testing.T, kid string) signingKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signingKey{kid, jose.RS256, k, &k.PublicKey}
}

func ecKey(t *testing.T, kid string) signingKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signingKey{kid, jose.ES256, k, &k.PublicKey}
}

func sign(t *testing.T, k signingKey, claims map[string]any) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: k.private},
		(&jose.SignerOptions{}).WithHeader("kid", k.kid).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// accessToken returns the claims of a Keycloak access token after token exchange.
func (is *issuer) accessToken(mod func(map[string]any)) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss":                is.srv.URL,
		"aud":                []string{audience, "account"},
		"sub":                "4f1c2d1e-alice",
		"azp":                "tasmofleet",
		"typ":                "Bearer",
		"scope":              "read write",
		"preferred_username": "alice",
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
	}
	if mod != nil {
		mod(c)
	}
	return c
}

func newVerifier(t *testing.T, is *issuer, cfg Config) *Verifier {
	cfg.Issuer, cfg.Audience = is.srv.URL, audience
	v, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidAccessToken(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	v := newVerifier(t, is, Config{})

	c, err := v.Verify(context.Background(), sign(t, k, is.accessToken(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "4f1c2d1e-alice" || c.Username != "alice" || c.Azp != "tasmofleet" {
		t.Errorf("claims = %+v", c)
	}
	if !c.HasScope("read") || !c.HasScope("write") || c.HasScope("admin") {
		t.Errorf("scopes = %v", c.Scopes)
	}
}

func TestES256Accepted(t *testing.T) {
	is := newIssuer(t)
	k := ecKey(t, "ec-1")
	is.publish(k)
	v := newVerifier(t, is, Config{})
	if _, err := v.Verify(context.Background(), sign(t, k, is.accessToken(nil))); err != nil {
		t.Fatal(err)
	}
}

func TestRejected(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	other := rsaKey(t, "rsa-1") // same kid, different key
	v := newVerifier(t, is, Config{})
	now := time.Now()

	cases := []struct {
		name string
		raw  func() string
	}{
		{"wrong iss", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { c["iss"] = "https://evil.example.org/realms/x" }))
		}},
		{"aud without security service", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { c["aud"] = []string{"account", "tasmofleet"} }))
		}},
		{"aud missing", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { delete(c, "aud") }))
		}},
		{"expired 1 s ago (no leeway on exp)", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }))
		}},
		{"nbf 10 min in the future", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { c["nbf"] = now.Add(10 * time.Minute).Unix() }))
		}},
		{"signed with another key", func() string { return sign(t, other, is.accessToken(nil)) }},
		{"alg none", func() string { return unsigned(is.accessToken(nil)) }},
		{"alg HS256 with the public key as secret", func() string { return hs256(t, k, is.accessToken(nil)) }},
		{"typ ID (Keycloak ID token)", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { c["typ"] = "ID" }))
		}},
		{"typ Refresh", func() string {
			return sign(t, k, is.accessToken(func(c map[string]any) { c["typ"] = "Refresh" }))
		}},
		{"payload changed after signing", func() string {
			raw := sign(t, k, is.accessToken(func(c map[string]any) { c["scope"] = "read" }))
			parts := strings.Split(raw, ".")
			p, _ := json.Marshal(is.accessToken(nil))
			parts[1] = base64.RawURLEncoding.EncodeToString(p)
			return strings.Join(parts, ".")
		}},
		{"garbage", func() string { return "not.a.jwt" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c, err := v.Verify(context.Background(), tc.raw()); err == nil {
				t.Fatalf("accepted: %+v", c)
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

// Only the configured algorithms are accepted, even if the key is published.
func TestAlgorithmRestricted(t *testing.T) {
	is := newIssuer(t)
	k := ecKey(t, "ec-1")
	is.publish(k)
	v := newVerifier(t, is, Config{Algorithms: []string{oidc.RS256}})
	if _, err := v.Verify(context.Background(), sign(t, k, is.accessToken(nil))); err == nil {
		t.Fatal("ES256 token accepted with Algorithms = [RS256]")
	}
}

// go-oidc checks nbf with a fixed leeway of 5 minutes and exp without leeway.
func TestTimeLeeway(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	v := newVerifier(t, is, Config{})
	raw := sign(t, k, is.accessToken(func(c map[string]any) { c["nbf"] = time.Now().Add(2 * time.Minute).Unix() }))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Errorf("nbf 2 min in the future rejected: %v", err)
	}
}

// go-oidc does not check azp; a token issued to any client with the right
// aud is accepted. PMSS logs azp in the audit only.
func TestAzpNotChecked(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	v := newVerifier(t, is, Config{})
	raw := sign(t, k, is.accessToken(func(c map[string]any) { c["azp"] = "some-other-client" }))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Errorf("rejected: %v", err)
	}
}

// Without the typ check of PMSS, go-oidc alone accepts a Keycloak ID token
// whose aud contains the security service.
func TestGoOIDCAloneAcceptsIDToken(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	provider, err := oidc.NewProvider(context.Background(), is.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	raw := sign(t, k, is.accessToken(func(c map[string]any) { c["typ"] = "ID" }))
	if _, err := provider.Verifier(&oidc.Config{ClientID: audience}).Verify(context.Background(), raw); err != nil {
		t.Errorf("go-oidc rejected the ID token itself: %v", err)
	}
}

// Key rotation: a new key is picked up on the first token with its kid.
func TestKeyRotation(t *testing.T) {
	is := newIssuer(t)
	k1 := rsaKey(t, "rsa-1")
	is.publish(k1)
	v := newVerifier(t, is, Config{MinRefreshInterval: time.Millisecond})
	if _, err := v.Verify(context.Background(), sign(t, k1, is.accessToken(nil))); err != nil {
		t.Fatal(err)
	}
	k2 := rsaKey(t, "rsa-2")
	is.publish(k2)
	time.Sleep(5 * time.Millisecond)
	if _, err := v.Verify(context.Background(), sign(t, k2, is.accessToken(nil))); err != nil {
		t.Fatalf("token with new kid rejected: %v", err)
	}
	if _, err := v.Verify(context.Background(), sign(t, k1, is.accessToken(nil))); err != nil {
		t.Fatalf("old key no longer accepted: %v", err)
	}
}

// go-oidc's RemoteKeySet fetches the JWKS for every token with an unknown kid.
func TestRemoteKeySetFetchesOnEveryUnknownKid(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	provider, err := oidc.NewProvider(context.Background(), is.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	v := provider.Verifier(&oidc.Config{ClientID: audience})
	before := is.fetches.Load()
	for i := range 10 {
		forged := rsaKey(t, "forged")
		forged.kid = "forged-" + string(rune('a'+i))
		v.Verify(context.Background(), sign(t, forged, is.accessToken(nil)))
	}
	if got := is.fetches.Load() - before; got != 10 {
		t.Errorf("JWKS fetches for 10 forged tokens = %d, want 10", got)
	}
}

// The throttled key set of PMSS fetches at most once per interval.
func TestThrottledKeySetLimitsFetches(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	v := newVerifier(t, is, Config{MinRefreshInterval: time.Hour})
	if _, err := v.Verify(context.Background(), sign(t, k, is.accessToken(nil))); err != nil {
		t.Fatal(err)
	}
	before := is.fetches.Load()
	for i := range 10 {
		forged := rsaKey(t, "forged")
		forged.kid = "forged-" + string(rune('a'+i))
		if _, err := v.Verify(context.Background(), sign(t, forged, is.accessToken(nil))); err == nil {
			t.Fatal("forged token accepted")
		}
	}
	if got := is.fetches.Load() - before; got != 0 {
		t.Errorf("JWKS fetches within the interval = %d, want 0", got)
	}
	// valid tokens still pass
	if _, err := v.Verify(context.Background(), sign(t, k, is.accessToken(nil))); err != nil {
		t.Fatal(err)
	}
}

func TestErrNotAccessToken(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	v := newVerifier(t, is, Config{})
	_, err := v.Verify(context.Background(), sign(t, k, is.accessToken(func(c map[string]any) { c["typ"] = "ID" })))
	if !errors.Is(err, ErrNotAccessToken) {
		t.Errorf("err = %v, want ErrNotAccessToken", err)
	}
}

// --- forged tokens ---

func unsigned(claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"rsa-1"}`))
	p, _ := json.Marshal(claims)
	return h + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

// hs256 signs with the public RSA key (as JWK JSON) as HMAC secret: the classic
// algorithm confusion attack.
func hs256(t *testing.T, k signingKey, claims map[string]any) string {
	secret, err := json.Marshal(jose.JSONWebKey{Key: k.public})
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithHeader("kid", k.kid))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(claims)
	jws, err := s.Sign(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := jws.CompactSerialize()
	return raw
}
