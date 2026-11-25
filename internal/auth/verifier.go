// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// Token type checks (design T-9).
const (
	// TypCheckBearer requires the claim typ = "Bearer" (Keycloak): ID and
	// refresh tokens are rejected.
	TypCheckBearer = "bearer"
	// TypCheckNone checks no typ (authentik sets no typ claim). Audience
	// and the scope claim keep ID tokens out.
	TypCheckNone = "none"
)

// VerifierConfig of the token check (design 7.5, T-7 to T-9).
type VerifierConfig struct {
	// Issuer is the fixed issuer of the OIDC provider, e.g. a Keycloak
	// realm URL or the issuer of an authentik provider. iss must match
	// exactly.
	Issuer string
	// Audience must be contained in aud.
	Audience string
	// JWKSURL is optional; empty means jwks_uri from the discovery
	// document of the issuer, fetched on first use.
	JWKSURL string
	// Algorithms allowed for signatures; default RS256 and ES256. none and
	// symmetric algorithms are never accepted.
	Algorithms []string
	// MinRefreshInterval between two JWKS fetches for unknown key IDs;
	// default 1 min.
	MinRefreshInterval time.Duration
	// HTTPClient for discovery and JWKS; default 10 s timeout.
	HTTPClient *http.Client
	// TypCheck is TypCheckBearer (default when empty) or TypCheckNone.
	TypCheck string
}

// ErrNotAccessToken is returned with TypCheckBearer for tokens whose typ
// claim is not "Bearer", e.g. ID or refresh tokens of Keycloak.
var ErrNotAccessToken = errors.New("token is not an access token (typ != Bearer)")

// ErrNoScope is returned for tokens without a scope claim; only access
// tokens carry one (specification 2.1, design T-9).
var ErrNoScope = errors.New("token without scope claim")

// Verifier checks access tokens of the OIDC provider with go-oidc plus the
// scope claim and, if configured, the token type. It needs no connection to
// the provider at start: discovery and JWKS are fetched on the first token.
type Verifier struct {
	v        *oidc.IDTokenVerifier
	Keys     *ThrottledKeySet
	typCheck string
}

// NewVerifier builds the verifier; it does not contact the issuer.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("issuer and audience are required")
	}
	typCheck := cfg.TypCheck
	if typCheck == "" {
		typCheck = TypCheckBearer
	}
	if typCheck != TypCheckBearer && typCheck != TypCheckNone {
		return nil, fmt.Errorf("typ check %q: want %q or %q", cfg.TypCheck, TypCheckBearer, TypCheckNone)
	}
	algs := cfg.Algorithms
	if len(algs) == 0 {
		algs = []string{oidc.RS256, oidc.ES256}
	}
	for _, a := range algs {
		if a == "none" || strings.HasPrefix(a, "HS") {
			return nil, fmt.Errorf("algorithm %s is not allowed", a)
		}
	}
	interval := cfg.MinRefreshInterval
	if interval == 0 {
		interval = time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	ks := &ThrottledKeySet{
		issuer: cfg.Issuer, jwksURL: cfg.JWKSURL, interval: interval, client: client,
	}
	for _, a := range algs {
		ks.algs = append(ks.algs, jose.SignatureAlgorithm(a))
	}
	return &Verifier{
		v: oidc.NewVerifier(cfg.Issuer, ks, &oidc.Config{
			ClientID:             cfg.Audience, // checked as "aud contains"
			SupportedSigningAlgs: algs,
		}),
		Keys:     ks,
		typCheck: typCheck,
	}, nil
}

// Verify checks the raw token and returns the caller.
func (v *Verifier) Verify(ctx context.Context, raw string) (Caller, error) {
	tok, err := v.v.Verify(ctx, raw)
	if err != nil {
		return Caller{}, err
	}
	var c struct {
		Typ               string  `json:"typ"`
		Scope             *string `json:"scope"`
		PreferredUsername string  `json:"preferred_username"`
		Azp               string  `json:"azp"`
	}
	if err := tok.Claims(&c); err != nil {
		return Caller{}, err
	}
	if v.typCheck == TypCheckBearer && c.Typ != "Bearer" {
		return Caller{}, ErrNotAccessToken
	}
	if c.Scope == nil {
		return Caller{}, ErrNoScope
	}
	if tok.Subject == "" {
		return Caller{}, errors.New("token without sub")
	}
	return Caller{Subject: tok.Subject, Username: c.PreferredUsername, Azp: c.Azp, Scopes: strings.Fields(*c.Scope)}, nil
}

// ThrottledKeySet is an oidc.KeySet that fetches the JWKS again for an
// unknown kid at most once per interval (T-7). go-oidc's RemoteKeySet
// fetches on every unknown kid, so every forged token would cause a
// request to Keycloak. Known keys are checked without waiting for a fetch.
type ThrottledKeySet struct {
	issuer   string
	algs     []jose.SignatureAlgorithm
	interval time.Duration
	client   *http.Client

	mu       sync.Mutex
	jwksURL  string
	keys     []jose.JSONWebKey
	next     time.Time // earliest next fetch
	fetching chan struct{}
	fetches  int
}

// retryAfterFailure is the wait after a failed fetch; shorter than the
// interval so that a Keycloak that was down at start is picked up soon.
const retryAfterFailure = 5 * time.Second

// Fetches returns the number of JWKS fetches, for tests and logs.
func (k *ThrottledKeySet) Fetches() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.fetches
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

	for attempt := 0; ; attempt++ {
		k.mu.Lock()
		if key, ok := k.find(kid); ok {
			k.mu.Unlock()
			return jws.Verify(key)
		}
		if k.fetching != nil && attempt == 0 {
			// Another request fetches already; wait for its result.
			ch := k.fetching
			k.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}
		if attempt > 0 || time.Now().Before(k.next) {
			k.mu.Unlock()
			return nil, fmt.Errorf("unknown key id %q (JWKS fetched at most every %s)", kid, k.interval)
		}
		k.fetching = make(chan struct{})
		k.next = time.Now().Add(k.interval)
		k.fetches++
		jwksURL := k.jwksURL
		k.mu.Unlock()

		keys, resolved, err := k.fetch(ctx, jwksURL)

		k.mu.Lock()
		if err == nil {
			k.keys, k.jwksURL = keys, resolved
		} else {
			k.next = time.Now().Add(retryAfterFailure)
		}
		close(k.fetching)
		k.fetching = nil
		k.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

func (k *ThrottledKeySet) find(kid string) (*jose.JSONWebKey, bool) {
	for i := range k.keys {
		if k.keys[i].KeyID == kid {
			return &k.keys[i], true
		}
	}
	return nil, false
}

// fetch loads the JWKS; with an empty URL it reads jwks_uri from the
// discovery document first and checks that it belongs to the issuer.
func (k *ThrottledKeySet) fetch(ctx context.Context, jwksURL string) ([]jose.JSONWebKey, string, error) {
	if jwksURL == "" {
		var meta struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		wellKnown := strings.TrimSuffix(k.issuer, "/") + "/.well-known/openid-configuration"
		if err := k.getJSON(ctx, wellKnown, &meta); err != nil {
			return nil, "", fmt.Errorf("discovery: %w", err)
		}
		if meta.Issuer != k.issuer {
			return nil, "", fmt.Errorf("discovery: issuer %q does not match the configured %q", meta.Issuer, k.issuer)
		}
		if meta.JWKSURI == "" {
			return nil, "", errors.New("discovery: no jwks_uri")
		}
		jwksURL = meta.JWKSURI
	}
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := k.getJSON(ctx, jwksURL, &raw); err != nil {
		return nil, "", fmt.Errorf("JWKS: %w", err)
	}
	var keys []jose.JSONWebKey
	for _, r := range raw.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(r); err != nil {
			continue // unsupported key type
		}
		if key.Use == "enc" || !key.IsPublic() {
			continue // Keycloak also publishes an encryption key
		}
		keys = append(keys, key)
	}
	return keys, jwksURL, nil
}

func (k *ThrottledKeySet) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
