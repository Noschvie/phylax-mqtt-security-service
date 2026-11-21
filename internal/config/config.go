// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config reads the configuration of the Security Service from
// environment variables. All variables start with PMSS_ and have defaults,
// so the service starts without any configuration.
package config

import (
	"errors"
	"fmt"
	"log/slog"
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
	}
}

// Load builds the configuration from the defaults and the environment.
// getenv is usually os.Getenv; tests pass their own function. All errors
// are reported together.
func Load(getenv func(string) string) (Config, error) {
	cfg := Default()
	var errs []error

	if v := strings.TrimSpace(getenv(EnvListenAddr)); v != "" {
		cfg.ListenAddr = v
	}

	if v := strings.TrimSpace(getenv(EnvLogLevel)); v != "" {
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
	}
	for _, d := range durations {
		v := strings.TrimSpace(getenv(d.env))
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

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}
