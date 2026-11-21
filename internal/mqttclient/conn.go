// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mqttclient holds the MQTT 5 connection of the Security Service to
// the admin listener of Mosquitto (design section 7.2, decision A-9):
//
//   - autopaho handles connecting and reconnecting.
//   - Clean session, session expiry 0: DynSec commands are not idempotent,
//     a session would resend an unacknowledged command after a reconnect.
//   - The response topic is subscribed in OnConnectionUp on every
//     connection; autopaho does not subscribe again by itself. Publish is
//     only allowed after the subscription is acknowledged.
//   - Without a connection, Publish waits until its context ends and then
//     returns ErrNotConnected. Nothing is queued or resent later.
package mqttclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// ErrNotConnected means the message was not handed to the broker: there was
// no ready connection until the context ended.
var ErrNotConnected = errors.New("no connection to the broker")

// Options of a connection.
type Options struct {
	BrokerURL *url.URL
	TLS       *tls.Config
	// ClientID of the connection; empty means "pmss-" plus 8 random bytes in hex.
	ClientID  string
	KeepAlive time.Duration
	// ResponseTopic is subscribed on every connection; Publish is possible
	// only after the broker acknowledged it.
	ResponseTopic string
	// ExtraTopics are subscribed together with ResponseTopic, e.g.
	// $SYS/broker/version. A refused extra topic is logged and does not
	// block Publish.
	ExtraTopics []string
	Logger      *slog.Logger

	// ConnectTimeout limits one connection attempt; default 10s.
	ConnectTimeout time.Duration
	// Backoff returns the wait before connection attempt n (0 = first
	// attempt); default 0, then 1s, 2s, 4s … up to 30s.
	Backoff func(attempt int) time.Duration
}

// Conn is a connection to the broker. Create it with New and start it
// with Start.
type Conn struct {
	opts Options

	mu    sync.Mutex
	cm    *autopaho.ConnectionManager
	gen   uint64        // counts connections; stale subscriptions are ignored
	ready chan struct{} // closed while subscribed; replaced when the connection drops
	up    bool
}

// New returns a connection that is not started yet.
func New(opts Options) *Conn {
	if opts.ClientID == "" {
		opts.ClientID = randomClientID()
	}
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	if opts.Backoff == nil {
		opts.Backoff = defaultBackoff
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Conn{opts: opts, ready: make(chan struct{})}
}

// ClientID returns the MQTT client ID of the connection.
func (c *Conn) ClientID() string { return c.opts.ClientID }

// Start connects in the background and keeps reconnecting until ctx ends
// or Close is called. onMessage receives every message on the response
// topic and the extra topics; it must not block for long.
func (c *Conn) Start(ctx context.Context, onMessage func(topic string, payload []byte)) error {
	wanted := map[string]bool{c.opts.ResponseTopic: true}
	for _, t := range c.opts.ExtraTopics {
		wanted[t] = true
	}
	cfg := autopaho.ClientConfig{
		ServerUrls: []*url.URL{c.opts.BrokerURL},
		TlsCfg:     c.opts.TLS,
		KeepAlive:  uint16(c.opts.KeepAlive / time.Second),
		// A-9: clean session, no session after the connection ends.
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         0,
		ConnectTimeout:                c.opts.ConnectTimeout,
		ReconnectBackoff:              c.opts.Backoff,
		OnConnectionUp:                c.onConnectionUp,
		OnConnectionDown:              c.onConnectionDown,
		OnConnectError: func(err error) {
			c.opts.Logger.Warn("broker connection attempt failed", "broker", c.opts.BrokerURL.String(), "error", err)
		},
		ClientConfig: paho.ClientConfig{
			ClientID: c.opts.ClientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					if wanted[pr.Packet.Topic] {
						onMessage(pr.Packet.Topic, pr.Packet.Payload)
					}
					return true, nil
				},
			},
			OnClientError: func(err error) {
				c.opts.Logger.Warn("broker connection error", "error", err)
			},
			OnServerDisconnect: func(d *paho.Disconnect) {
				reason := ""
				if d.Properties != nil {
					reason = d.Properties.ReasonString
				}
				c.opts.Logger.Warn("broker closed the connection", "reason_code", d.ReasonCode, "reason", reason)
			},
		},
	}

	cm, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		return fmt.Errorf("mqtt: %w", err)
	}
	c.mu.Lock()
	c.cm = cm
	c.mu.Unlock()
	return nil
}

// onConnectionUp must not block (autopaho); the subscription runs in its
// own goroutine.
func (c *Conn) onConnectionUp(cm *autopaho.ConnectionManager, connack *paho.Connack) {
	c.mu.Lock()
	c.gen++
	gen := c.gen
	c.up = true
	c.mu.Unlock()
	c.opts.Logger.Info("broker connected", "broker", c.opts.BrokerURL.String(),
		"client_id", c.opts.ClientID, "session_present", connack.SessionPresent)
	go c.subscribe(cm, gen)
}

func (c *Conn) onConnectionDown() bool {
	c.mu.Lock()
	c.gen++
	c.up = false
	select {
	case <-c.ready:
		c.ready = make(chan struct{})
	default:
	}
	c.mu.Unlock()
	c.opts.Logger.Warn("broker connection lost; reconnecting")
	return true // keep reconnecting
}

// subscribe subscribes the response topic for connection gen. It retries
// while this connection is up, because Publish is blocked until it succeeds.
func (c *Conn) subscribe(cm *autopaho.ConnectionManager, gen uint64) {
	for attempt := 0; ; attempt++ {
		if !c.current(gen) {
			return
		}
		subs := []paho.SubscribeOptions{{Topic: c.opts.ResponseTopic, QoS: 1}}
		for _, t := range c.opts.ExtraTopics {
			subs = append(subs, paho.SubscribeOptions{Topic: t, QoS: 0})
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.opts.ConnectTimeout)
		suback, err := cm.Subscribe(ctx, &paho.Subscribe{Subscriptions: subs})
		cancel()
		if err == nil && len(suback.Reasons) == len(subs) && suback.Reasons[0] < 0x80 {
			for i, t := range c.opts.ExtraTopics {
				if code := suback.Reasons[i+1]; code >= 0x80 {
					c.opts.Logger.Warn("subscription refused", "topic", t, "reason_code", code)
				}
			}
			c.mu.Lock()
			if c.gen == gen {
				select {
				case <-c.ready:
				default:
					close(c.ready)
				}
			}
			c.mu.Unlock()
			c.opts.Logger.Info("response topic subscribed", "topic", c.opts.ResponseTopic)
			return
		}
		if err == nil {
			// Not authorized (0x87) is a configuration error, e.g. a missing
			// role_security_manager; it stays so until the role is fixed.
			err = fmt.Errorf("unexpected suback reason codes % x", suback.Reasons)
		}
		c.opts.Logger.Error("subscribing the response topic failed", "topic", c.opts.ResponseTopic, "error", err)
		time.Sleep(c.opts.Backoff(attempt + 1))
	}
}

func (c *Conn) current(gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up && c.gen == gen
}

// Ready reports whether the connection is up and the response topic is
// subscribed.
func (c *Conn) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.ready:
		return true
	default:
		return false
	}
}

// Publish sends payload with QoS 1 and waits for the PUBACK. It waits for a
// ready connection until ctx ends.
//
// Errors:
//   - ErrNotConnected (wrapped): not handed to the broker.
//   - ctx.Err() (wrapped): ctx ended while publishing. The broker may have
//     received and executed the message (A-9: state unknown).
//   - *PubackError: the broker refused the message, e.g. not authorized.
func (c *Conn) Publish(ctx context.Context, topic string, payload []byte) error {
	for {
		c.mu.Lock()
		ready, cm := c.ready, c.cm
		c.mu.Unlock()
		if cm == nil {
			return fmt.Errorf("%w: connection not started", ErrNotConnected)
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrNotConnected, ctx.Err())
		}

		resp, err := cm.Publish(ctx, &paho.Publish{Topic: topic, QoS: 1, Payload: payload})
		switch {
		case errors.Is(err, autopaho.ConnectionDownError):
			// Dropped between the check and the call; nothing was sent.
			// Wait for the next connection (onConnectionDown replaces ready).
			c.waitDown(ctx, ready)
			continue
		case err != nil && ctx.Err() != nil:
			return fmt.Errorf("publish: %w", ctx.Err())
		case err != nil:
			return fmt.Errorf("publish: %w", err)
		case resp != nil && resp.ReasonCode >= 0x80:
			return &PubackError{ReasonCode: resp.ReasonCode, Reason: pubackReason(resp)}
		}
		return nil
	}
}

// waitDown avoids a busy loop when Publish sees ConnectionDownError before
// onConnectionDown has replaced the ready channel.
func (c *Conn) waitDown(ctx context.Context, old chan struct{}) {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		c.mu.Lock()
		changed := c.ready != old
		c.mu.Unlock()
		if changed {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Close disconnects and stops reconnecting.
func (c *Conn) Close(ctx context.Context) error {
	c.mu.Lock()
	cm := c.cm
	c.mu.Unlock()
	if cm == nil {
		return nil
	}
	err := cm.Disconnect(ctx)
	if errors.Is(err, autopaho.ConnectionDownError) {
		return nil
	}
	return err
}

// PubackError is a PUBACK with a reason code of 0x80 or higher.
type PubackError struct {
	ReasonCode byte
	Reason     string
}

func (e *PubackError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("broker refused the message: reason code 0x%02x (%s)", e.ReasonCode, e.Reason)
	}
	return fmt.Sprintf("broker refused the message: reason code 0x%02x", e.ReasonCode)
}

func pubackReason(r *paho.PublishResponse) string {
	if r.Properties != nil {
		return r.Properties.ReasonString
	}
	return ""
}

// defaultBackoff: autopaho calls it before every attempt, attempt 0 is the
// first connection and starts at once; then 1s, 2s, 4s … up to 30s.
func defaultBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	d := time.Second
	for i := 1; i < attempt && d < 30*time.Second; i++ {
		d *= 2
	}
	return min(d, 30*time.Second)
}

func randomClientID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return "pmss-" + hex.EncodeToString(b)
}
