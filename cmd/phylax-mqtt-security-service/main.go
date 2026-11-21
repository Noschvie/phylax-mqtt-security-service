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
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/api"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/mqttclient"
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

	// Certificates are loaded once; every error stops the start (design 5.2).
	tlsCfg, identity, err := mqttclient.LoadTLS(cfg.MQTT.CAFile, cfg.MQTT.CertFile, cfg.MQTT.KeyFile, cfg.MQTT.TLSServerName())
	if err != nil {
		logger.Error("invalid broker TLS configuration", "error", err)
		return 1
	}
	logger.Info("admin identity loaded", "cn", identity.CommonName, "not_after", identity.NotAfter.UTC().Format(time.RFC3339))
	if time.Until(identity.NotAfter) < 0 {
		logger.Error("admin certificate has expired; the broker will refuse the connection", "cn", identity.CommonName)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The broker connection runs in the background and reconnects by
	// itself; the HTTP server starts without waiting for it.
	conn := mqttclient.New(mqttclient.Options{
		BrokerURL:     cfg.MQTT.BrokerURL,
		TLS:           tlsCfg,
		ClientID:      cfg.MQTT.ClientID,
		KeepAlive:     cfg.MQTT.KeepAlive,
		ResponseTopic: dynsec.ResponseTopic,
		ExtraTopics:   []string{brokerVersionTopic},
		Logger:        logger.With("component", "mqtt"),
	})
	dyn := dynsec.NewClient(conn, cfg.MQTT.CommandTimeout, logger.With("component", "dynsec"))
	var brokerVersion atomic.Value // string from $SYS/broker/version
	brokerVersion.Store("")
	connCtx, cancelConn := context.WithCancel(context.Background())
	defer cancelConn()
	onMessage := func(topic string, payload []byte) {
		switch topic {
		case dynsec.ResponseTopic:
			dyn.HandleMessage(payload)
		case brokerVersionTopic:
			brokerVersion.Store(parseBrokerVersion(string(payload)))
		}
	}
	if err := conn.Start(connCtx, onMessage); err != nil {
		logger.Error("broker connection", "error", err)
		return 1
	}

	authorizer, err := newAuthorizer(cfg.OIDC, logger)
	if err != nil {
		logger.Error("invalid token check configuration", "error", err)
		return 1
	}
	handler := api.NewHandler(api.Options{
		Logger:          logger,
		Version:         version,
		Managed:         cfg.Managed,
		MaxRequestBytes: cfg.MaxRequestBytes,
		DynSec:          dyn,
		Auth:            authorizer,
		BrokerVersion:   func() string { return brokerVersion.Load().(string) },
	})
	srv := api.NewServer(cfg, handler, logger)
	err = runServer(ctx, srv, cfg.ShutdownTimeout, logger)

	// Disconnect from the broker after the last request.
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
	if cerr := conn.Close(closeCtx); cerr != nil {
		logger.Warn("broker disconnect", "error", cerr)
	}
	cancelClose()

	if err != nil {
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

// newAuthorizer returns the token check for Keycloak access tokens, or
// DenyAll without an issuer: the API is closed unless configured.
func newAuthorizer(cfg config.OIDC, logger *slog.Logger) (auth.Authorizer, error) {
	if cfg.Issuer == "" {
		logger.Warn("PMSS_OIDC_ISSUER not set; all /api/v1 requests are refused")
		return auth.DenyAll{}, nil
	}
	if cfg.AllowHTTP {
		logger.Warn("PMSS_OIDC_ALLOW_HTTP is set; token keys may be fetched over plain HTTP (test setups only)")
	}
	v, err := auth.NewVerifier(auth.VerifierConfig{
		Issuer:             cfg.Issuer,
		Audience:           cfg.Audience,
		JWKSURL:            cfg.JWKSURL,
		MinRefreshInterval: cfg.JWKSMinRefresh,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("token check configured", "issuer", cfg.Issuer, "audience", cfg.Audience,
		"scope_read", cfg.ScopeRead, "scope_write", cfg.ScopeWrite)
	return &auth.Bearer{
		Verifier:   v,
		ScopeNames: map[auth.Scope]string{auth.ScopeRead: cfg.ScopeRead, auth.ScopeWrite: cfg.ScopeWrite},
		Logger:     logger.With("component", "auth"),
	}, nil
}

// brokerVersionTopic is retained by Mosquitto, e.g. "mosquitto version 2.1.2";
// role_security_manager may read $SYS/# (design 6.2).
const brokerVersionTopic = "$SYS/broker/version"

// parseBrokerVersion returns "2.1.2" from "mosquitto version 2.1.2".
func parseBrokerVersion(payload string) string {
	payload = strings.TrimSpace(payload)
	if i := strings.LastIndexByte(payload, ' '); i >= 0 {
		return payload[i+1:]
	}
	return payload
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
