// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"log/slog"
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
	if cfg != Default() {
		t.Errorf("got %+v, want defaults %+v", cfg, Default())
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
	}
	if cfg != want {
		t.Errorf("got %+v, want %+v", cfg, want)
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
	}))
	if err == nil {
		t.Fatal("Load: want error")
	}
	for _, name := range []string{EnvLogLevel, EnvShutdownTimeout, EnvWriteTimeout, EnvIdleTimeout} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name %s: %v", name, err)
		}
	}
}
