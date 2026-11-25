// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("got %+v, want defaults %+v", cfg, Default())
	}
	if got := cfg.MQTT.BrokerURL.String(); got != "mqtts://mosquitto:8884" {
		t.Errorf("default broker URL %q", got)
	}
	if got := cfg.MQTT.TLSServerName(); got != "mosquitto" {
		t.Errorf("default server name %q, want mosquitto", got)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		EnvListenAddr:         "127.0.0.1:9000",
		EnvLogLevel:           "debug",
		EnvShutdownTimeout:    "5s",
		EnvReadHeaderTimeout:  "2s",
		EnvReadTimeout:        "10s",
		EnvWriteTimeout:       "1m",
		EnvIdleTimeout:        "2m",
		EnvMQTTBrokerURL:      "mqtts://127.0.0.1:18884",
		EnvMQTTServerName:     "mosquitto",
		EnvMQTTCAFile:         "/certs/ca.crt",
		EnvMQTTCertFile:       "/certs/admin.crt",
		EnvMQTTKeyFile:        "/certs/admin.key",
		EnvMQTTClientID:       "pmss-test",
		EnvMQTTKeepAlive:      "10s",
		EnvDynsecTimeout:      "3s",
		EnvRolePrefix:         "x_",
		EnvGroupPrefix:        "y_",
		EnvClientMarker:       "managed-by: other",
		EnvMaxRequestBytes:    "2097152",
		EnvOIDCIssuer:         "http://127.0.0.1:8180/realms/pmss-test",
		EnvOIDCAudience:       "pmss",
		EnvOIDCJWKSURL:        "http://keycloak:8080/realms/pmss-test/protocol/openid-connect/certs",
		EnvOIDCScopeRead:      "pmss.read",
		EnvOIDCScopeWrite:     "pmss.write",
		EnvOIDCAllowHTTP:      "true",
		EnvOIDCJWKSMinRefresh: "30s",
		EnvOIDCTypCheck:       "none",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		ListenAddr:        "127.0.0.1:9000",
		LogLevel:          slog.LevelDebug,
		ShutdownTimeout:   5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxRequestBytes:   2 << 20,
		Managed:           Managed{RolePrefix: "x_", GroupPrefix: "y_", ClientMarker: "managed-by: other"},
		OIDC: OIDC{
			Issuer: "http://127.0.0.1:8180/realms/pmss-test", Audience: "pmss",
			JWKSURL:   "http://keycloak:8080/realms/pmss-test/protocol/openid-connect/certs",
			ScopeRead: "pmss.read", ScopeWrite: "pmss.write", AllowHTTP: true, JWKSMinRefresh: 30 * time.Second,
			TypCheck: "none",
		},
		MQTT: MQTT{
			BrokerURL:      &url.URL{Scheme: "mqtts", Host: "127.0.0.1:18884"},
			ServerName:     "mosquitto",
			CAFile:         "/certs/ca.crt",
			CertFile:       "/certs/admin.crt",
			KeyFile:        "/certs/admin.key",
			ClientID:       "pmss-test",
			KeepAlive:      10 * time.Second,
			CommandTimeout: 3 * time.Second,
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("got %+v, want %+v", cfg, want)
	}
	if got := cfg.MQTT.TLSServerName(); got != "mosquitto" {
		t.Errorf("server name %q, want mosquitto", got)
	}
}

func TestLoadLogLevelCaseInsensitive(t *testing.T) {
	cfg, err := Load(env(map[string]string{EnvLogLevel: "WARN"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != slog.LevelWarn {
		t.Errorf("got %v, want warn", cfg.LogLevel)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{
		EnvLogLevel:        "verbose",
		EnvShutdownTimeout: "soon",
		EnvWriteTimeout:    "0s",
		EnvIdleTimeout:     "-1s",
		EnvMQTTKeepAlive:   "1500ms",
		EnvMQTTBrokerURL:   "mqtt://mosquitto:1883",
	}))
	if err == nil {
		t.Fatal("Load: want error")
	}
	for _, name := range []string{EnvLogLevel, EnvShutdownTimeout, EnvWriteTimeout, EnvIdleTimeout, EnvMQTTKeepAlive, EnvMQTTBrokerURL} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name %s: %v", name, err)
		}
	}
}

func TestLoadBrokerURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"mqtts://mosquitto:8884", "mqtts://mosquitto:8884", true},
		{"mqtts://mosquitto:8884/", "mqtts://mosquitto:8884", true},
		{"mqtts://[::1]:8884", "mqtts://[::1]:8884", true},
		{"mqtt://mosquitto:1883", "", false},
		{"ssl://mosquitto:8884", "", false},
		{"mqtts://mosquitto", "", false},
		{"mqtts://admin:secret@mosquitto:8884", "", false},
		{"mqtts://mosquitto:8884/x", "", false},
		{"://bad", "", false},
	} {
		cfg, err := Load(env(map[string]string{EnvMQTTBrokerURL: tc.in}))
		if (err == nil) != tc.ok {
			t.Errorf("%q: err %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && cfg.MQTT.BrokerURL.String() != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, cfg.MQTT.BrokerURL, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%q: error shows the password: %v", tc.in, err)
		}
	}
}

func TestLoadCommandTimeoutBelowWriteTimeout(t *testing.T) {
	_, err := Load(env(map[string]string{EnvDynsecTimeout: "30s"}))
	if err == nil || !strings.Contains(err.Error(), EnvDynsecTimeout) {
		t.Errorf("want error for %s >= %s, got %v", EnvDynsecTimeout, EnvWriteTimeout, err)
	}
}

func TestLoadManagedAndLimits(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxRequestBytes != MinRequestBytes || cfg.Managed != (Managed{"tf_", "tf_", "managed-by: pmss"}) {
		t.Errorf("defaults %d %+v", cfg.MaxRequestBytes, cfg.Managed)
	}
	for name, e := range map[string]map[string]string{
		"limit below 1 MiB":         {EnvMaxRequestBytes: "1048575"},
		"limit not a number":        {EnvMaxRequestBytes: "1M"},
		"role prefix pmss-":         {EnvRolePrefix: "pmss-"},
		"role prefix of reserved":   {EnvRolePrefix: "role_"},
		"group prefix inside pmss-": {EnvGroupPrefix: "pm"},
	} {
		if _, err := Load(env(e)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadOIDC(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Issuer != "" || cfg.OIDC.Audience != "phylax-mqtt-security-service" || cfg.OIDC.ScopeRead != "read" || cfg.OIDC.ScopeWrite != "write" || cfg.OIDC.TypCheck != "bearer" {
		t.Errorf("defaults %+v", cfg.OIDC)
	}
	if _, err := Load(env(map[string]string{EnvOIDCIssuer: "https://kc.example.org/realms/pmss"})); err != nil {
		t.Errorf("https issuer: %v", err)
	}
	for name, e := range map[string]map[string]string{
		"http without allow": {EnvOIDCIssuer: "http://kc.example.org/realms/pmss"},
		"relative":           {EnvOIDCIssuer: "/realms/pmss"},
		"other scheme":       {EnvOIDCIssuer: "ftp://kc.example.org/realms/pmss"},
		"query":              {EnvOIDCIssuer: "https://kc.example.org/realms/pmss?x=1"},
		"jwks over http":     {EnvOIDCIssuer: "https://kc.example.org/realms/pmss", EnvOIDCJWKSURL: "http://keycloak/certs"},
		"allow not a bool":   {EnvOIDCAllowHTTP: "yes please"},
		"same scope names":   {EnvOIDCScopeRead: "x", EnvOIDCScopeWrite: "x"},
		"unknown typ check":  {EnvOIDCTypCheck: "Bearer"},
	} {
		if _, err := Load(env(e)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
