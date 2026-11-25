// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config reads the configuration of the Security Service from
// environment variables. All variables start with PMSS_ and have defaults
// that match the container layout of the design (section 5.3).
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Environment variables read by Load.
const (
	EnvListenAddr        = "PMSS_LISTEN_ADDR"
	EnvLogLevel          = "PMSS_LOG_LEVEL"
	EnvShutdownTimeout   = "PMSS_SHUTDOWN_TIMEOUT"
	EnvReadHeaderTimeout = "PMSS_HTTP_READ_HEADER_TIMEOUT"
	EnvReadTimeout       = "PMSS_HTTP_READ_TIMEOUT"
	EnvWriteTimeout      = "PMSS_HTTP_WRITE_TIMEOUT"
	EnvIdleTimeout       = "PMSS_HTTP_IDLE_TIMEOUT"

	EnvMQTTBrokerURL  = "PMSS_MQTT_BROKER_URL"
	EnvMQTTServerName = "PMSS_MQTT_SERVER_NAME"
	EnvMQTTCAFile     = "PMSS_MQTT_CA_FILE"
	EnvMQTTCertFile   = "PMSS_MQTT_CERT_FILE"
	EnvMQTTKeyFile    = "PMSS_MQTT_KEY_FILE"
	EnvMQTTClientID   = "PMSS_MQTT_CLIENT_ID"
	EnvMQTTKeepAlive  = "PMSS_MQTT_KEEPALIVE"
	EnvDynsecTimeout  = "PMSS_DYNSEC_TIMEOUT"

	EnvRolePrefix      = "PMSS_ROLE_PREFIX"
	EnvGroupPrefix     = "PMSS_GROUP_PREFIX"
	EnvClientMarker    = "PMSS_CLIENT_MARKER"
	EnvMaxRequestBytes = "PMSS_MAX_REQUEST_BYTES"

	EnvOIDCIssuer         = "PMSS_OIDC_ISSUER"
	EnvOIDCAudience       = "PMSS_OIDC_AUDIENCE"
	EnvOIDCJWKSURL        = "PMSS_OIDC_JWKS_URL"
	EnvOIDCScopeRead      = "PMSS_OIDC_SCOPE_READ"
	EnvOIDCScopeWrite     = "PMSS_OIDC_SCOPE_WRITE"
	EnvOIDCAllowHTTP      = "PMSS_OIDC_ALLOW_HTTP"
	EnvOIDCJWKSMinRefresh = "PMSS_OIDC_JWKS_MIN_REFRESH"
	EnvOIDCTypCheck       = "PMSS_OIDC_TYP_CHECK"
)

// MinRequestBytes is the smallest allowed body limit (specification S-11).
const MinRequestBytes = 1 << 20

// Config of the Security Service.
type Config struct {
	// ListenAddr is the address of the HTTP server, e.g. ":8080".
	ListenAddr string
	// LogLevel is the minimum level of log records.
	LogLevel slog.Level
	// ShutdownTimeout is how long open requests may run after SIGTERM.
	ShutdownTimeout time.Duration

	// Timeouts of the HTTP server (design section 7.3).
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

	// MaxRequestBytes limits request bodies; at least MinRequestBytes.
	MaxRequestBytes int64

	// Managed says which DynSec objects the service may change (design 6.4).
	Managed Managed

	// OIDC is the token check (design 7.5).
	OIDC OIDC

	// MQTT holds the connection to the Dynamic Security Control API.
	MQTT MQTT
}

// OIDC holds the token check. Without Issuer the API refuses every request.
type OIDC struct {
	// Issuer is the fixed issuer of the OIDC provider (Keycloak realm URL,
	// issuer of the authentik provider); iss must match exactly.
	Issuer string
	// Audience must be contained in aud (client ID of the service).
	Audience string
	// JWKSURL overrides jwks_uri from the discovery document, e.g. an
	// internal address of the provider.
	JWKSURL string
	// ScopeRead and ScopeWrite are the scope names in the token.
	ScopeRead  string
	ScopeWrite string
	// AllowHTTP permits http:// for Issuer and JWKSURL (test setups only).
	AllowHTTP bool
	// JWKSMinRefresh is the minimum time between two JWKS fetches for
	// unknown key IDs (T-7).
	JWKSMinRefresh time.Duration
	// TypCheck is "bearer" (typ claim must be "Bearer", Keycloak) or
	// "none" (no typ check, authentik); design T-9.
	TypCheck string
}

// Managed holds the marks of managed objects. They are configurable so that
// the interface is not tied to TasmoFleet (design 6.4).
type Managed struct {
	RolePrefix   string // e.g. tf_
	GroupPrefix  string // e.g. tf_
	ClientMarker string // textdescription of managed clients, e.g. "managed-by: pmss"
}

// MQTT is the connection to the broker (design sections 5.2, 7.2).
type MQTT struct {
	// BrokerURL is the internal admin listener, scheme mqtts, e.g.
	// mqtts://mosquitto:8884.
	BrokerURL *url.URL
	// ServerName is checked against the SAN of the broker certificate.
	// Empty means the host of BrokerURL.
	ServerName string
	// CAFile holds the certificate of the server CA (only this CA is trusted).
	CAFile string
	// CertFile and KeyFile are the client certificate of the admin CA,
	// e.g. CN=pmss-admin. The CN is the DynSec user; there is no password.
	CertFile string
	KeyFile  string
	// ClientID of the MQTT connection. Empty means "pmss-" plus random hex,
	// so two instances never take over each other's connection.
	ClientID string
	// KeepAlive of the MQTT connection, whole seconds.
	KeepAlive time.Duration
	// CommandTimeout limits a single DynSec command: waiting for the
	// connection, publishing and waiting for the response (A-9).
	CommandTimeout time.Duration
}

// Default returns the configuration used when no variable is set.
func Default() Config {
	return Config{
		ListenAddr:        ":8080",
		LogLevel:          slog.LevelInfo,
		ShutdownTimeout:   15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxRequestBytes:   MinRequestBytes,
		OIDC: OIDC{
			Audience:       "phylax-mqtt-security-service",
			ScopeRead:      "read",
			ScopeWrite:     "write",
			JWKSMinRefresh: time.Minute,
			TypCheck:       "bearer",
		},
		Managed: Managed{
			RolePrefix:   "tf_",
			GroupPrefix:  "tf_",
			ClientMarker: "managed-by: pmss",
		},
		MQTT: MQTT{
			BrokerURL:      &url.URL{Scheme: "mqtts", Host: "mosquitto:8884"},
			CAFile:         "/run/mqtt-server-ca/ca.crt",
			CertFile:       "/run/secrets/mqtt-client/pmss-admin.crt",
			KeyFile:        "/run/secrets/mqtt-client/pmss-admin.key",
			KeepAlive:      30 * time.Second,
			CommandTimeout: 5 * time.Second,
		},
	}
}

// Load builds the configuration from the defaults and the environment.
// getenv is usually os.Getenv; tests pass their own function. All errors
// are reported together.
func Load(getenv func(string) string) (Config, error) {
	cfg := Default()
	var errs []error
	get := func(name string) string { return strings.TrimSpace(getenv(name)) }

	if v := get(EnvListenAddr); v != "" {
		cfg.ListenAddr = v
	}

	if v := get(EnvLogLevel); v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("%s: unknown level %q (debug, info, warn, error)", EnvLogLevel, v))
		}
	}

	durations := []struct {
		env string
		dst *time.Duration
	}{
		{EnvShutdownTimeout, &cfg.ShutdownTimeout},
		{EnvReadHeaderTimeout, &cfg.ReadHeaderTimeout},
		{EnvReadTimeout, &cfg.ReadTimeout},
		{EnvWriteTimeout, &cfg.WriteTimeout},
		{EnvIdleTimeout, &cfg.IdleTimeout},
		{EnvMQTTKeepAlive, &cfg.MQTT.KeepAlive},
		{EnvOIDCJWKSMinRefresh, &cfg.OIDC.JWKSMinRefresh},
		{EnvDynsecTimeout, &cfg.MQTT.CommandTimeout},
	}
	for _, d := range durations {
		v := get(d.env)
		if v == "" {
			continue
		}
		parsed, err := time.ParseDuration(v)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: invalid duration %q, e.g. 15s", d.env, v))
		case parsed <= 0:
			errs = append(errs, fmt.Errorf("%s: must be greater than 0, got %q", d.env, v))
		default:
			*d.dst = parsed
		}
	}

	if v := get(EnvMQTTBrokerURL); v != "" {
		u, err := url.Parse(v)
		switch {
		// The value is not repeated in the errors: it could contain a password.
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: invalid URL", EnvMQTTBrokerURL))
		case u.Scheme != "mqtts":
			// mTLS is mandatory at the admin listener (design 4.1, SEC-03).
			errs = append(errs, fmt.Errorf("%s: scheme must be mqtts, got %q", EnvMQTTBrokerURL, u.Scheme))
		case u.Hostname() == "" || u.Port() == "":
			errs = append(errs, fmt.Errorf("%s: host and port required, e.g. mqtts://mosquitto:8884", EnvMQTTBrokerURL))
		case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "":
			errs = append(errs, fmt.Errorf("%s: no user, path or query allowed", EnvMQTTBrokerURL))
		default:
			cfg.MQTT.BrokerURL = &url.URL{Scheme: u.Scheme, Host: u.Host}
		}
	}
	for _, s := range []struct {
		env string
		dst *string
	}{
		{EnvMQTTServerName, &cfg.MQTT.ServerName},
		{EnvMQTTCAFile, &cfg.MQTT.CAFile},
		{EnvMQTTCertFile, &cfg.MQTT.CertFile},
		{EnvMQTTKeyFile, &cfg.MQTT.KeyFile},
		{EnvMQTTClientID, &cfg.MQTT.ClientID},
		{EnvRolePrefix, &cfg.Managed.RolePrefix},
		{EnvGroupPrefix, &cfg.Managed.GroupPrefix},
		{EnvClientMarker, &cfg.Managed.ClientMarker},
		{EnvOIDCIssuer, &cfg.OIDC.Issuer},
		{EnvOIDCAudience, &cfg.OIDC.Audience},
		{EnvOIDCJWKSURL, &cfg.OIDC.JWKSURL},
		{EnvOIDCScopeRead, &cfg.OIDC.ScopeRead},
		{EnvOIDCScopeWrite, &cfg.OIDC.ScopeWrite},
	} {
		if v := get(s.env); v != "" {
			*s.dst = v
		}
	}

	if v := get(EnvOIDCAllowHTTP); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: true or false, got %q", EnvOIDCAllowHTTP, v))
		}
		cfg.OIDC.AllowHTTP = b
	}
	for _, u := range []struct{ env, val string }{
		{EnvOIDCIssuer, cfg.OIDC.Issuer},
		{EnvOIDCJWKSURL, cfg.OIDC.JWKSURL},
	} {
		if u.val == "" {
			continue
		}
		if err := checkOIDCURL(u.val, cfg.OIDC.AllowHTTP); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u.env, err))
		}
	}
	if v := get(EnvOIDCTypCheck); v != "" {
		switch v {
		case "bearer", "none":
			cfg.OIDC.TypCheck = v
		default:
			errs = append(errs, fmt.Errorf("%s: bearer or none, got %q", EnvOIDCTypCheck, v))
		}
	}
	if cfg.OIDC.ScopeRead == cfg.OIDC.ScopeWrite {
		errs = append(errs, fmt.Errorf("%s and %s must differ", EnvOIDCScopeRead, EnvOIDCScopeWrite))
	}

	if v := get(EnvMaxRequestBytes); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: not a number of bytes: %q", EnvMaxRequestBytes, v))
		case n < MinRequestBytes:
			errs = append(errs, fmt.Errorf("%s: at least %d (1 MiB), got %d", EnvMaxRequestBytes, MinRequestBytes, n))
		default:
			cfg.MaxRequestBytes = n
		}
	}
	// A prefix must not reach into the reserved names (pmss-*,
	// role_security_manager), or admin objects would count as managed.
	for _, p := range []struct{ env, val string }{
		{EnvRolePrefix, cfg.Managed.RolePrefix},
		{EnvGroupPrefix, cfg.Managed.GroupPrefix},
	} {
		if strings.HasPrefix(p.val, "pmss-") || strings.HasPrefix("pmss-", p.val) ||
			strings.HasPrefix("role_security_manager", p.val) {
			errs = append(errs, fmt.Errorf("%s: %q overlaps the reserved names pmss-* and role_security_manager", p.env, p.val))
		}
	}

	if ka := cfg.MQTT.KeepAlive; ka%time.Second != 0 || ka > 65535*time.Second {
		errs = append(errs, fmt.Errorf("%s: whole seconds up to 65535s, got %s", EnvMQTTKeepAlive, ka))
	}
	// A request waits for the DynSec response; it has to fit into the
	// write timeout of the HTTP server.
	if cfg.MQTT.CommandTimeout >= cfg.WriteTimeout {
		errs = append(errs, fmt.Errorf("%s (%s) must be shorter than %s (%s)",
			EnvDynsecTimeout, cfg.MQTT.CommandTimeout, EnvWriteTimeout, cfg.WriteTimeout))
	}

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

// checkOIDCURL: absolute https URL (http only with allowHTTP), without
// user, query or fragment. A JWKS over plain HTTP would let anyone on the
// path inject signing keys.
func checkOIDCURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return errors.New("not an absolute URL")
	case u.Scheme == "http" && !allowHTTP:
		return fmt.Errorf("http is only allowed with %s=true", EnvOIDCAllowHTTP)
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("scheme must be https, got %q", u.Scheme)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return errors.New("no user, query or fragment allowed")
	}
	return nil
}

// TLSServerName returns the name checked against the broker certificate.
func (m MQTT) TLSServerName() string {
	if m.ServerName != "" {
		return m.ServerName
	}
	return m.BrokerURL.Hostname()
}
