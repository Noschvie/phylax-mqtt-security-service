// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

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

	jose "github.com/go-jose/go-jose/v4"
)

const audience = "phylax-mqtt-security-service"

// issuer is a minimal OIDC provider: discovery document and JWKS.
type issuer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	keys      []jose.JSONWebKey
	jwks      atomic.Int32
	discovery atomic.Int32
	down      atomic.Bool
	issuerURL string // what discovery reports; default the server URL
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	is := &issuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		is.discovery.Add(1)
		if is.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		iss := is.issuerURL
		if iss == "" {
			iss = is.srv.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": is.srv.URL + "/jwks"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		is.jwks.Add(1)
		if is.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		is.mu.Lock()
		defer is.mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: is.keys})
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
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

func (is *issuer) publish(k signingKey) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.keys = append(is.keys, jose.JSONWebKey{Key: k.public, KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
}

func sign(t *testing.T, k signingKey, claims map[string]any) string {
	t.Helper()
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

// claims of a Keycloak access token after token exchange.
func (is *issuer) claims(mod func(map[string]any)) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": is.srv.URL, "aud": []string{audience, "account"}, "sub": "4f1c2d1e-alice",
		"azp": "tasmofleet", "typ": "Bearer", "scope": "read write", "preferred_username": "alice",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if mod != nil {
		mod(c)
	}
	return c
}

func newTestVerifier(t *testing.T, is *issuer, cfg VerifierConfig) *Verifier {
	t.Helper()
	cfg.Issuer, cfg.Audience = is.srv.URL, audience
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyValid(t *testing.T) {
	is := newIssuer(t)
	k, e := rsaKey(t, "rsa-1"), ecKey(t, "ec-1")
	is.publish(k)
	is.publish(e)
	v := newTestVerifier(t, is, VerifierConfig{})

	for _, key := range []signingKey{k, e} {
		c, err := v.Verify(context.Background(), sign(t, key, is.claims(nil)))
		if err != nil {
			t.Fatalf("%s: %v", key.alg, err)
		}
		if c.Subject != "4f1c2d1e-alice" || c.Username != "alice" || c.Azp != "tasmofleet" || !c.HasScope("read") || !c.HasScope("write") {
			t.Errorf("%s: caller %+v", key.alg, c)
		}
	}
	if is.discovery.Load() != 1 || is.jwks.Load() != 1 {
		t.Errorf("discovery %d, jwks %d; want one each", is.discovery.Load(), is.jwks.Load())
	}
}

func TestVerifyRejected(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "rsa-1")
	is.publish(k)
	v := newTestVerifier(t, is, VerifierConfig{})
	other := rsaKey(t, "rsa-1") // same kid, other key

	hs := func() string {
		// HS256 with the public key as secret (key confusion).
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(strings.Repeat("public-key-bytes", 4))},
			(&jose.SignerOptions{}).WithHeader("kid", "rsa-1"))
		if err != nil {
			t.Fatal(err)
		}
		p, _ := json.Marshal(is.claims(nil))
		jws, err := s.Sign(p)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := jws.CompactSerialize()
		return raw
	}
	none := func() string {
		enc := base64.RawURLEncoding
		h := enc.EncodeToString([]byte(`{"alg":"none","kid":"rsa-1"}`))
		p, _ := json.Marshal(is.claims(nil))
		return h + "." + enc.EncodeToString(p) + "."
	}
	tampered := func() string {
		parts := strings.Split(sign(t, k, is.claims(nil)), ".")
		p, _ := json.Marshal(is.claims(func(c map[string]any) { c["scope"] = "read write admin" }))
		parts[1] = base64.RawURLEncoding.EncodeToString(p)
		return strings.Join(parts, ".")
	}

	for name, raw := range map[string]string{
		"wrong iss":       sign(t, k, is.claims(func(c map[string]any) { c["iss"] = "https://evil.example.org/realms/pmss" })),
		"aud without us":  sign(t, k, is.claims(func(c map[string]any) { c["aud"] = []string{"account"} })),
		"aud missing":     sign(t, k, is.claims(func(c map[string]any) { delete(c, "aud") })),
		"expired":         sign(t, k, is.claims(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Second).Unix() })),
		"exp missing":     sign(t, k, is.claims(func(c map[string]any) { delete(c, "exp") })),
		"nbf 10 min":      sign(t, k, is.claims(func(c map[string]any) { c["nbf"] = time.Now().Add(10 * time.Minute).Unix() })),
		"ID token":        sign(t, k, is.claims(func(c map[string]any) { c["typ"] = "ID" })),
		"refresh token":   sign(t, k, is.claims(func(c map[string]any) { c["typ"] = "Refresh" })),
		"typ missing":     sign(t, k, is.claims(func(c map[string]any) { delete(c, "typ") })),
		"sub missing":     sign(t, k, is.claims(func(c map[string]any) { delete(c, "sub") })),
		"other key":       sign(t, other, is.claims(nil)),
		"payload changed": tampered(),
		"HS256":           hs(),
		"alg none":        none(),
		"garbage":         "not.a.token",
	} {
		if c, err := v.Verify(context.Background(), raw); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
	if _, err := v.Verify(context.Background(), sign(t, k, is.claims(func(c map[string]any) { c["typ"] = "ID" }))); !errors.Is(err, ErrNotAccessToken) {
		t.Errorf("ID token: %v, want ErrNotAccessToken", err)
	}
}

func TestVerifyAlgorithmsRestricted(t *testing.T) {
	is := newIssuer(t)
	e := ecKey(t, "ec-1")
	is.publish(e)
	v := newTestVerifier(t, is, VerifierConfig{Algorithms: []string{"RS256"}})
	if _, err := v.Verify(context.Background(), sign(t, e, is.claims(nil))); err == nil {
		t.Error("ES256 accepted with algorithm list [RS256]")
	}
	for _, bad := range []string{"none", "HS256"} {
		if _, err := NewVerifier(VerifierConfig{Issuer: is.srv.URL, Audience: audience, Algorithms: []string{bad}}); err == nil {
			t.Errorf("algorithm %s allowed", bad)
		}
	}
}

func TestKeyRotationAndThrottle(t *testing.T) {
	is := newIssuer(t)
	k1 := rsaKey(t, "k1")
	is.publish(k1)
	v := newTestVerifier(t, is, VerifierConfig{MinRefreshInterval: 200 * time.Millisecond})
	ctx := context.Background()
	if _, err := v.Verify(ctx, sign(t, k1, is.claims(nil))); err != nil {
		t.Fatal(err)
	}

	// Forged tokens with unknown kids: at most one fetch per interval.
	forged := rsaKey(t, "unknown")
	for range 10 {
		if _, err := v.Verify(ctx, sign(t, forged, is.claims(nil))); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if n := v.Keys.Fetches(); n != 2 {
		t.Errorf("%d JWKS fetches for 10 unknown kids, want 2 (start + one refresh)", n)
	}

	// Rotation: a new key is taken over once the interval has passed.
	k2 := rsaKey(t, "k2")
	is.publish(k2)
	time.Sleep(250 * time.Millisecond)
	if _, err := v.Verify(ctx, sign(t, k2, is.claims(nil))); err != nil {
		t.Errorf("rotated key: %v", err)
	}
	// Known keys never wait for a fetch.
	if _, err := v.Verify(ctx, sign(t, k1, is.claims(nil))); err != nil {
		t.Errorf("old key: %v", err)
	}
}

func TestConcurrentFirstTokensFetchOnce(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "k1")
	is.publish(k)
	v := newTestVerifier(t, is, VerifierConfig{})
	raw := sign(t, k, is.claims(nil))
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), raw); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := is.jwks.Load(); n != 1 {
		t.Errorf("%d JWKS fetches, want 1", n)
	}
}

// TestIssuerDownAtStart: the verifier needs no Keycloak at start and
// retries soon after a failed fetch.
func TestIssuerDownAtStart(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "k1")
	is.publish(k)
	is.down.Store(true)
	v := newTestVerifier(t, is, VerifierConfig{})
	raw := sign(t, k, is.claims(nil))
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("accepted while the issuer is down")
	}
	is.down.Store(false)
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("retried before retryAfterFailure")
	}
	v.Keys.mu.Lock()
	v.Keys.next = time.Now() // skip the wait of retryAfterFailure
	v.Keys.mu.Unlock()
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Errorf("after the issuer is back: %v", err)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "k1")
	is.publish(k)
	is.issuerURL = "https://other.example.org/realms/pmss"
	v := newTestVerifier(t, is, VerifierConfig{})
	_, err := v.Verify(context.Background(), sign(t, k, is.claims(nil)))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error %v, want issuer mismatch", err)
	}
}

func TestJWKSURLSkipsDiscovery(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "k1")
	is.publish(k)
	v := newTestVerifier(t, is, VerifierConfig{JWKSURL: is.srv.URL + "/jwks"})
	if _, err := v.Verify(context.Background(), sign(t, k, is.claims(nil))); err != nil {
		t.Fatal(err)
	}
	if is.discovery.Load() != 0 {
		t.Error("discovery fetched although a JWKS URL is configured")
	}
}

func TestEncryptionKeysIgnored(t *testing.T) {
	is := newIssuer(t)
	k := rsaKey(t, "k1")
	is.mu.Lock()
	is.keys = append(is.keys, jose.JSONWebKey{Key: k.public, KeyID: k.kid, Algorithm: "RSA-OAEP", Use: "enc"})
	is.mu.Unlock()
	v := newTestVerifier(t, is, VerifierConfig{})
	if _, err := v.Verify(context.Background(), sign(t, k, is.claims(nil))); err == nil {
		t.Error("token signed with an encryption key accepted")
	}
}
