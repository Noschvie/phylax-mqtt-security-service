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
		EnvListenAddr:        "127.0.0.1:9000",
		EnvLogLevel:          "debug",
		EnvShutdownTimeout:   "5s",
		EnvReadHeaderTimeout: "2s",
		EnvReadTimeout:       "10s",
		EnvWriteTimeout:      "1m",
		EnvIdleTimeout:       "2m",
		EnvMQTTBrokerURL:     "mqtts://127.0.0.1:18884",
		EnvMQTTServerName:    "mosquitto",
		EnvMQTTCAFile:        "/certs/ca.crt",
		EnvMQTTCertFile:      "/certs/admin.crt",
		EnvMQTTKeyFile:       "/certs/admin.key",
		EnvMQTTClientID:      "pmss-test",
		EnvMQTTKeepAlive:     "10s",
		EnvDynsecTimeout:     "3s",
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
