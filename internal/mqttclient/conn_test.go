// SPDX-License-Identifier: AGPL-3.0-or-later

package mqttclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// writeCert creates a certificate signed by parent (self-signed if nil)
// and writes cert and key as PEM into dir.
func writeCert(t *testing.T, dir, name string, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	must(t, os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testPKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ca, caKey := writeCert(t, dir, "ca", &x509.Certificate{
		Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	writeCert(t, dir, "admin", &x509.Certificate{
		Subject: pkix.Name{CommonName: "pmss-admin"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)
	writeCert(t, dir, "nocn", &x509.Certificate{
		Subject: pkix.Name{Organization: []string{"x"}}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)
	writeCert(t, dir, "server", &x509.Certificate{
		Subject: pkix.Name{CommonName: "mosquitto"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey)
	return dir
}

func TestLoadTLS(t *testing.T) {
	dir := testPKI(t)
	p := func(n string) string { return filepath.Join(dir, n) }

	cfg, id, err := LoadTLS(p("ca.crt"), p("admin.crt"), p("admin.key"), "mosquitto")
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}
	if id.CommonName != "pmss-admin" || id.NotAfter.IsZero() {
		t.Errorf("identity %+v", id)
	}
	if cfg.ServerName != "mosquitto" || cfg.MinVersion != tls.VersionTLS12 || cfg.InsecureSkipVerify ||
		cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Errorf("tls.Config %+v", cfg)
	}

	notPEM := p("garbage.crt")
	must(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))

	for name, tc := range map[string]struct {
		ca, cert, key, server, want string
	}{
		"no server name":   {p("ca.crt"), p("admin.crt"), p("admin.key"), "", "server name"},
		"missing CA":       {p("missing.crt"), p("admin.crt"), p("admin.key"), "mosquitto", "server CA"},
		"CA without PEM":   {notPEM, p("admin.crt"), p("admin.key"), "mosquitto", "no PEM certificate"},
		"missing cert":     {p("ca.crt"), p("missing.crt"), p("admin.key"), "mosquitto", "client certificate"},
		"key mismatch":     {p("ca.crt"), p("admin.crt"), p("server.key"), "mosquitto", "client certificate"},
		"no CN":            {p("ca.crt"), p("nocn.crt"), p("nocn.key"), "mosquitto", "no CN"},
		"server cert only": {p("ca.crt"), p("server.crt"), p("server.key"), "mosquitto", "clientAuth"},
	} {
		_, _, err := LoadTLS(tc.ca, tc.cert, tc.key, tc.server)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: error contains key material", name)
		}
	}
}

func TestPublishNotStarted(t *testing.T) {
	c := New(Options{})
	if err := c.Publish(context.Background(), "t", nil); !errors.Is(err, ErrNotConnected) {
		t.Errorf("error %v, want ErrNotConnected", err)
	}
	if c.Ready() {
		t.Error("ready without connection")
	}
}

// TestPublishWithoutBroker: nothing listens; Publish waits until the
// context ends and reports that nothing was sent.
func TestPublishWithoutBroker(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	addr := ln.Addr().String()
	ln.Close()

	dir := testPKI(t)
	cfg, _, err := LoadTLS(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key"), "mosquitto")
	must(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := New(Options{
		BrokerURL: &url.URL{Scheme: "mqtts", Host: addr}, TLS: cfg, KeepAlive: 30 * time.Second,
		ResponseTopic: "r", Backoff: func(int) time.Duration { return 50 * time.Millisecond },
	})
	must(t, c.Start(ctx, func([]byte) {}))
	defer c.Close(context.Background())

	pctx, pcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer pcancel()
	err = c.Publish(pctx, "t", []byte("x"))
	if !errors.Is(err, ErrNotConnected) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v, want ErrNotConnected after the deadline", err)
	}
}

func TestDefaultBackoff(t *testing.T) {
	want := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := defaultBackoff(i); got != w {
			t.Errorf("attempt %d: %s, want %s", i, got, w)
		}
	}
	if got := defaultBackoff(1000); got != 30*time.Second {
		t.Errorf("attempt 1000: %s", got)
	}
}

func TestRandomClientID(t *testing.T) {
	a, b := New(Options{}).ClientID(), New(Options{}).ClientID()
	if !regexp.MustCompile(`^pmss-[0-9a-f]{16}$`).MatchString(a) || a == b {
		t.Errorf("client IDs %q, %q", a, b)
	}
	if id := New(Options{ClientID: "fixed"}).ClientID(); id != "fixed" {
		t.Errorf("client ID %q, want fixed", id)
	}
}

func TestPubackError(t *testing.T) {
	if s := (&PubackError{ReasonCode: 0x87, Reason: "not authorized"}).Error(); !strings.Contains(s, "0x87") || !strings.Contains(s, "not authorized") {
		t.Errorf("message %q", s)
	}
}
