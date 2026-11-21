// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dynsec sends commands to the Mosquitto Dynamic Security Control
// API and matches the responses (design section 7.2, decision A-9).
//
// Each Execute call sends one command with its own correlationData (a UUID
// string) on $CONTROL/dynamic-security/v1. The plugin answers every
// subscriber of the response topic, so responses with an unknown or
// missing correlationData are normal (mosquitto_ctrl, a second instance)
// and are dropped. Changing commands are never repeated automatically.
package dynsec

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/mqttclient"
)

// Topics of the Control API.
const (
	RequestTopic  = "$CONTROL/dynamic-security/v1"
	ResponseTopic = "$CONTROL/dynamic-security/v1/response"
)

var (
	// ErrUnavailable: no connection to the broker; the command was not
	// sent and will not be sent later. Maps to 503 broker_unavailable.
	ErrUnavailable = errors.New("dynsec: broker unavailable")
	// ErrTimeout: no response in time. The command may have been executed;
	// a changing caller reads the object back (A-9). Maps to 504
	// broker_timeout.
	ErrTimeout = errors.New("dynsec: no response from the broker")
)

// CommandError is an error reported by the plugin for a command, e.g.
// "Client not found".
type CommandError struct {
	Command string
	Message string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("dynsec %s: %s", e.Command, e.Message)
}

// NotFound reports whether the object of the command does not exist.
func (e *CommandError) NotFound() bool { return strings.HasSuffix(e.Message, "not found") }

// AlreadyExists reports whether the object to create exists already.
func (e *CommandError) AlreadyExists() bool { return strings.HasSuffix(e.Message, "already exists") }

// Command is a DynSec command. Its JSON encoding holds the parameters;
// Execute adds "command" and "correlationData".
type Command interface {
	CommandName() string
}

// Publisher sends a message to the broker; *mqttclient.Conn implements it.
// Errors wrapping mqttclient.ErrNotConnected mean the message was not sent.
type Publisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

// Client executes commands. Pass HandleMessage as message handler of the
// connection.
type Client struct {
	pub     Publisher
	timeout time.Duration
	logger  *slog.Logger

	mu      sync.Mutex
	pending map[string]chan response
}

// NewClient returns a client that gives each command at most timeout,
// including waiting for the connection.
func NewClient(pub Publisher, timeout time.Duration, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Client{pub: pub, timeout: timeout, logger: logger, pending: make(map[string]chan response)}
}

// response is one entry of the "responses" list.
type response struct {
	Command         string          `json:"command"`
	Error           string          `json:"error,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
	CorrelationData *string         `json:"correlationData,omitempty"`
}

// Execute sends cmd and returns the "data" of the response (may be empty).
//
// Errors: ErrUnavailable (not sent), ErrTimeout (state unknown),
// *CommandError (the plugin refused the command), context.Canceled (the
// caller gave up; state unknown) or another error (e.g. refused PUBACK,
// broker_error).
func (c *Client) Execute(ctx context.Context, cmd Command) (json.RawMessage, error) {
	id := newUUID()
	payload, err := encode(cmd, id)
	if err != nil {
		return nil, err
	}

	ch := make(chan response, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	name := cmd.CommandName()
	if err := c.pub.Publish(ctx, RequestTopic, payload); err != nil {
		switch {
		case errors.Is(err, mqttclient.ErrNotConnected):
			return nil, fmt.Errorf("%w: %s not sent: %w", ErrUnavailable, name, err)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, fmt.Errorf("%w: %s, publish not confirmed", ErrTimeout, name)
		case errors.Is(err, context.Canceled):
			return nil, fmt.Errorf("dynsec %s: %w (state unknown)", name, err)
		default:
			return nil, fmt.Errorf("dynsec %s: %w", name, err)
		}
	}

	select {
	case r := <-ch:
		if r.Error != "" {
			return nil, &CommandError{Command: r.Command, Message: r.Error}
		}
		return r.Data, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %s after %s", ErrTimeout, name, c.timeout)
		}
		return nil, fmt.Errorf("dynsec %s: %w (state unknown)", name, ctx.Err())
	}
}

// HandleMessage takes a message from the response topic and hands each
// response to the waiting Execute call. It never blocks.
func (c *Client) HandleMessage(payload []byte) {
	var msg struct {
		Responses []response `json:"responses"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		c.logger.Warn("dynsec: response is not valid JSON; dropped", "error", err)
		return
	}
	for _, r := range msg.Responses {
		if r.CorrelationData == nil {
			// The plugin omits correlationData only for broken requests
			// (invalid JSON, wrong type); ours are never broken, so this
			// belongs to someone else or is a bug. The data is not logged.
			c.logger.Debug("dynsec: response without correlationData dropped", "command", r.Command, "error", r.Error)
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[*r.CorrelationData]
		if ok {
			delete(c.pending, *r.CorrelationData) // at most one response per request
		}
		c.mu.Unlock()
		if !ok {
			c.logger.Debug("dynsec: response for another client dropped", "command", r.Command)
			continue
		}
		ch <- r // buffered, single sender
	}
}

// encode returns {"commands":[{<cmd fields>, "command":…, "correlationData":…}]}.
func encode(cmd Command, id string) ([]byte, error) {
	fields := map[string]json.RawMessage{}
	raw, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("dynsec %s: encode: %w", cmd.CommandName(), err)
	}
	if string(raw) != "{}" && string(raw) != "null" {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("dynsec %s: command must encode as a JSON object: %w", cmd.CommandName(), err)
		}
	}
	for _, reserved := range []string{"command", "correlationData"} {
		if _, ok := fields[reserved]; ok {
			return nil, fmt.Errorf("dynsec %s: field %q is set by Execute", cmd.CommandName(), reserved)
		}
	}
	fields["command"], _ = json.Marshal(cmd.CommandName())
	fields["correlationData"], _ = json.Marshal(id) // always a string (design 7.2)
	return json.Marshal(map[string]any{"commands": []any{fields}})
}

// newUUID returns a random UUID (version 4).
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
