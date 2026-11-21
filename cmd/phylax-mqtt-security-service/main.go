// SPDX-License-Identifier: AGPL-3.0-or-later

// Command phylax-mqtt-security-service runs the Phylax MQTT Security
// Service: a REST API for managing Mosquitto Dynamic Security clients,
// roles and access control.
//
// Usage:
//
//	phylax-mqtt-security-service              run the service
//	phylax-mqtt-security-service healthcheck  check /healthz of a running service (exit 0 or 1)
//	phylax-mqtt-security-service version      print the version
//
// The configuration comes from environment variables (see README).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/api"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "too many arguments: %v\n", args)
		return 2
	}

	switch cmd {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "healthcheck":
		cfg, err := config.Load(getenv)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := healthcheck(healthURL(cfg.ListenAddr), 3*time.Second); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "":
		return serve(getenv, stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q (healthcheck, version)\n", cmd)
		return 2
	}
}

// serve runs the service until SIGINT or SIGTERM and then shuts down
// gracefully (design section 7.3). Logs go to stdout as JSON.
func serve(getenv func(string) string, stdout io.Writer) int {
	cfg, err := config.Load(getenv)
	if err != nil {
		// No logger yet: report the configuration error as a JSON record too.
		slog.New(slog.NewJSONHandler(stdout, nil)).Error("invalid configuration", "error", err)
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := api.NewServer(cfg, api.NewHandler(logger), logger)
	if err := runServer(ctx, srv, cfg.ShutdownTimeout, logger); err != nil {
		logger.Error("server stopped with error", "error", err)
		return 1
	}
	return 0
}

// runServer serves until ctx is cancelled, then waits up to timeout for
// open requests.
func runServer(ctx context.Context, srv *http.Server, timeout time.Duration, logger *slog.Logger) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	logger.Info("service started", "version", version, "addr", ln.Addr().String())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down", "timeout", timeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	logger.Info("service stopped")
	return nil
}

// healthURL derives the URL of /healthz on the local host from the listen
// address: ":8080" and "0.0.0.0:8080" become "http://127.0.0.1:8080/healthz".
func healthURL(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "http://" + listenAddr + "/healthz"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// healthcheck is used by the container HEALTHCHECK; the runtime image has
// no curl.
func healthcheck(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s returned %s", url, resp.Status)
	}
	return nil
}
