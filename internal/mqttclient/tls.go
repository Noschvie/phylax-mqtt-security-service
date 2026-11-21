// SPDX-License-Identifier: AGPL-3.0-or-later

package mqttclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
)

// Identity is the admin identity from the client certificate. The broker
// takes the CN as DynSec user name (use_identity_as_username, design 5.2).
type Identity struct {
	CommonName string
	NotAfter   time.Time
}

// LoadTLS builds the TLS configuration for the admin listener (design
// 5.1, 5.2, SEC-04): only the server CA in caFile is trusted, the broker
// certificate must match serverName, the client certificate comes from the
// admin CA. Every error stops the start of the service.
func LoadTLS(caFile, certFile, keyFile, serverName string) (*tls.Config, Identity, error) {
	if serverName == "" {
		return nil, Identity{}, errors.New("TLS server name is empty")
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, Identity{}, fmt.Errorf("server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, Identity{}, fmt.Errorf("server CA: no PEM certificate in %s", caFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// The error of LoadX509KeyPair never contains key material.
		return nil, Identity{}, fmt.Errorf("client certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, Identity{}, fmt.Errorf("client certificate %s: %w", certFile, err)
	}
	if leaf.Subject.CommonName == "" {
		return nil, Identity{}, fmt.Errorf("client certificate %s: no CN, the broker needs it as user name", certFile)
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasClientAuth(leaf.ExtKeyUsage) {
		return nil, Identity{}, fmt.Errorf("client certificate %s: extendedKeyUsage without clientAuth", certFile)
	}

	cfg := &tls.Config{
		RootCAs:      pool, // only the server CA, not the system trust store (SEC-13)
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName, // SAN check
		MinVersion:   tls.VersionTLS12,
	}
	return cfg, Identity{CommonName: leaf.Subject.CommonName, NotAfter: leaf.NotAfter}, nil
}

func hasClientAuth(usages []x509.ExtKeyUsage) bool {
	for _, u := range usages {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
