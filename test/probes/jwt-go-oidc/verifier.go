// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jwtprobe checks coreos/go-oidc as the JWT library of PMSS
// (design section 7.5, SEC-15) and holds a template for internal/auth:
// go-oidc verifies signature, iss, aud, exp, nbf and the algorithm;
// PMSS adds the token type, the scopes and a throttled JWKS refresh.
package jwtprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// Config of the token check. All values come from environment variables in PMSS.
type Config struct {
	Issuer             string        // Keycloak realm URL, e.g. https://kc.example.org/realms/pmss
	Audience           string        // must be contained in aud, e.g. phylax-mqtt-security-service
	Algorithms         []string      // allowed signature algorithms; default RS256, ES256
	MinRefreshInterval time.Duration // minimum time between two JWKS fetches; default 1 min
}

// Claims PMSS needs from an access token.
type Claims struct {
	Subject  string
	Username string // preferred_username, for the audit
	Azp      string // client the token was issued to, for the audit
	Scopes   []string
}

// HasScope reports whether the token carries the scope.
func (c *Claims) HasScope(s string) bool { return slices.Contains(c.Scopes, s) }

// Verifier checks Keycloak access tokens.
type Verifier struct {
	v *oidc.IDTokenVerifier
}

// ErrNotAccessToken is returned for tokens whose typ claim is not "Bearer"
// (e.g. ID or refresh tokens of Keycloak).
var ErrNotAccessToken = errors.New("token is not an access token (typ != Bearer)")

// New discovers the issuer and builds the verifier.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, err
	}
	algs := cfg.Algorithms
	if len(algs) == 0 {
		algs = []string{oidc.RS256, oidc.ES256}
	}
	interval := cfg.MinRefreshInterval
	if interval == 0 {
		interval = time.Minute
	}
	ks := NewThrottledKeySet(meta.JWKSURI, algs, interval)
	return &Verifier{v: oidc.NewVerifier(cfg.Issuer, ks, &oidc.Config{
		ClientID:             cfg.Audience, // checked as "aud contains"
		SupportedSigningAlgs: algs,
	})}, nil
}

// Verify checks the raw token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := v.v.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var c struct {
		Typ               string `json:"typ"`
		Scope             string `json:"scope"`
		PreferredUsername string `json:"preferred_username"`
		Azp               string `json:"azp"`
	}
	if err := tok.Claims(&c); err != nil {
		return nil, err
	}
	if c.Typ != "Bearer" {
		return nil, ErrNotAccessToken
	}
	return &Claims{Subject: tok.Subject, Username: c.PreferredUsername, Azp: c.Azp,
		Scopes: strings.Fields(c.Scope)}, nil
}

// ThrottledKeySet is an oidc.KeySet that fetches the JWKS again for an
// unknown kid at most once per interval. go-oidc's RemoteKeySet fetches on
// every unknown kid, so every forged token would cause a request to Keycloak.
type ThrottledKeySet struct {
	url      string
	algs     []jose.SignatureAlgorithm
	interval time.Duration
	client   *http.Client

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetched time.Time
	Fetches int // number of JWKS fetches, for tests
}

func NewThrottledKeySet(url string, algs []string, interval time.Duration) *ThrottledKeySet {
	ks := &ThrottledKeySet{url: url, interval: interval, client: &http.Client{Timeout: 10 * time.Second}}
	for _, a := range algs {
		ks.algs = append(ks.algs, jose.SignatureAlgorithm(a))
	}
	return ks
}

// VerifySignature implements oidc.KeySet.
func (k *ThrottledKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, k.algs)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID

	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.find(kid); ok {
		return jws.Verify(key)
	}
	if !k.fetched.IsZero() && time.Since(k.fetched) < k.interval {
		return nil, fmt.Errorf("unknown key id %q (JWKS refresh throttled)", kid)
	}
	if err := k.refresh(ctx); err != nil {
		return nil, err
	}
	if key, ok := k.find(kid); ok {
		return jws.Verify(key)
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (k *ThrottledKeySet) find(kid string) (*jose.JSONWebKey, bool) {
	for i := range k.keys {
		if k.keys[i].KeyID == kid {
			return &k.keys[i], true
		}
	}
	return nil, false
}

func (k *ThrottledKeySet) refresh(ctx context.Context) error {
	k.fetched = time.Now()
	k.Fetches++
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	var keys []jose.JSONWebKey
	for _, r := range raw.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(r); err != nil {
			continue // unsupported key type
		}
		if key.Use == "enc" {
			continue // Keycloak also publishes an encryption key
		}
		keys = append(keys, key)
	}
	k.keys = keys
	return nil
}
