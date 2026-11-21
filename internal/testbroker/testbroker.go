// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testbroker connects integration tests to the test broker of
// test/integration/broker. Only for tests. The tests run only if
// PMSS_TEST_BROKER_URL is set:
//
//	PMSS_TEST_BROKER_URL          e.g. mqtts://127.0.0.1:18884
//	PMSS_TEST_BROKER_CERTS        directory created by make-certs.sh (…/run/certs)
//	PMSS_TEST_BROKER_SERVER_NAME  SAN to check, default mosquitto
package testbroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/mqttclient"
)

// Broker is the test broker from the environment.
type Broker struct {
	URL        *url.URL
	Certs      string
	ServerName string
}

// FromEnv returns the test broker or skips the test.
func FromEnv(t testing.TB) Broker {
	t.Helper()
	raw := os.Getenv("PMSS_TEST_BROKER_URL")
	if raw == "" {
		t.Skip("PMSS_TEST_BROKER_URL not set; see test/integration/broker")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("PMSS_TEST_BROKER_URL: %v", err)
	}
	b := Broker{URL: u, Certs: os.Getenv("PMSS_TEST_BROKER_CERTS"), ServerName: os.Getenv("PMSS_TEST_BROKER_SERVER_NAME")}
	if b.Certs == "" {
		t.Fatal("PMSS_TEST_BROKER_CERTS not set")
	}
	if b.ServerName == "" {
		b.ServerName = "mosquitto"
	}
	return b
}

// Logger writes to stderr with -v, otherwise nowhere.
func Logger(t testing.TB) *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("test", t.Name())
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Options of Connect.
type Options struct {
	Cert        string // name of the client certificate in Certs, e.g. pmss-admin
	Addr        string // host:port, default the broker URL (e.g. a proxy)
	WaitReady   bool   // fail unless subscribed within 10 s
	ExtraTopics []string
	OnExtra     func(topic string, payload []byte)
}

// Connect opens a connection and returns the DynSec client.
func Connect(t testing.TB, b Broker, o Options) (*mqttclient.Conn, *dynsec.Client) {
	t.Helper()
	tlsCfg, id, err := mqttclient.LoadTLS(filepath.Join(b.Certs, "server-ca.crt"),
		filepath.Join(b.Certs, o.Cert+".crt"), filepath.Join(b.Certs, o.Cert+".key"), b.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	addr := o.Addr
	if addr == "" {
		addr = b.URL.Host
	}
	logger := Logger(t).With("identity", id.CommonName)
	conn := mqttclient.New(mqttclient.Options{
		BrokerURL:      &url.URL{Scheme: "mqtts", Host: addr},
		TLS:            tlsCfg,
		KeepAlive:      30 * time.Second,
		ResponseTopic:  dynsec.ResponseTopic,
		ExtraTopics:    o.ExtraTopics,
		Logger:         logger,
		ConnectTimeout: 2 * time.Second,
		Backoff:        func(int) time.Duration { return 100 * time.Millisecond },
	})
	client := dynsec.NewClient(conn, 5*time.Second, logger)
	ctx, cancel := context.WithCancel(context.Background())
	onMessage := func(topic string, payload []byte) {
		if topic == dynsec.ResponseTopic {
			client.HandleMessage(payload)
		} else if o.OnExtra != nil {
			o.OnExtra(topic, payload)
		}
	}
	if err := conn.Start(ctx, onMessage); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = conn.Close(closeCtx)
		cancel()
	})
	if o.WaitReady {
		WaitFor(t, 10*time.Second, conn.Ready, "connection ready")
	}
	return conn, client
}

// WaitFor polls cond until it is true or d has passed.
func WaitFor(t testing.TB, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// RandomName returns prefix plus 8 random hex digits.
func RandomName(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// Must runs cmd and fails the test on error.
func Must(t testing.TB, c *dynsec.Client, cmd dynsec.Command) {
	t.Helper()
	if _, err := c.Execute(context.Background(), cmd); err != nil {
		t.Fatalf("%s: %v", cmd.CommandName(), err)
	}
}

// Changing DynSec commands for preparing test data; the service gets its
// own with the write endpoints.

type ACL struct {
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Allow    bool   `json:"allow"`
	Priority int    `json:"priority,omitempty"`
}

type RoleRef struct {
	Rolename string `json:"rolename"`
	Priority *int   `json:"priority,omitempty"`
}

type CreateClient struct {
	Username        string    `json:"username"`
	Password        string    `json:"password,omitempty"`
	Textname        string    `json:"textname,omitempty"`
	Textdescription string    `json:"textdescription,omitempty"`
	Roles           []RoleRef `json:"roles,omitempty"`
}

func (CreateClient) CommandName() string { return "createClient" }

type DeleteClient struct {
	Username string `json:"username"`
}

func (DeleteClient) CommandName() string { return "deleteClient" }

type DisableClient struct {
	Username string `json:"username"`
}

func (DisableClient) CommandName() string { return "disableClient" }

type EnableClient struct {
	Username string `json:"username"`
}

func (EnableClient) CommandName() string { return "enableClient" }

type CreateGroup struct {
	Groupname string `json:"groupname"`
	Textname  string `json:"textname,omitempty"`
}

func (CreateGroup) CommandName() string { return "createGroup" }

type DeleteGroup struct {
	Groupname string `json:"groupname"`
}

func (DeleteGroup) CommandName() string { return "deleteGroup" }

type CreateRole struct {
	Rolename string `json:"rolename"`
	Textname string `json:"textname,omitempty"`
	ACLs     []ACL  `json:"acls,omitempty"`
}

func (CreateRole) CommandName() string { return "createRole" }

type DeleteRole struct {
	Rolename string `json:"rolename"`
}

func (DeleteRole) CommandName() string { return "deleteRole" }

type AddClientRole struct {
	Username string `json:"username"`
	Rolename string `json:"rolename"`
	Priority *int   `json:"priority,omitempty"`
}

func (AddClientRole) CommandName() string { return "addClientRole" }

type RemoveClientRole struct {
	Username string `json:"username"`
	Rolename string `json:"rolename"`
}

func (RemoveClientRole) CommandName() string { return "removeClientRole" }

type AddGroupClient struct {
	Groupname string `json:"groupname"`
	Username  string `json:"username"`
}

func (AddGroupClient) CommandName() string { return "addGroupClient" }

type RemoveGroupClient struct {
	Groupname string `json:"groupname"`
	Username  string `json:"username"`
}

func (RemoveGroupClient) CommandName() string { return "removeGroupClient" }

type AddGroupRole struct {
	Groupname string `json:"groupname"`
	Rolename  string `json:"rolename"`
}

func (AddGroupRole) CommandName() string { return "addGroupRole" }
