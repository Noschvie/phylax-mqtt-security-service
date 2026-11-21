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
)

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

	// MQTT holds the connection to the Dynamic Security Control API.
	MQTT MQTT
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
	} {
		if v := get(s.env); v != "" {
			*s.dst = v
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

// TLSServerName returns the name checked against the broker certificate.
func (m MQTT) TLSServerName() string {
	if m.ServerName != "" {
		return m.ServerName
	}
	return m.BrokerURL.Hostname()
}
