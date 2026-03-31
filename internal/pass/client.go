// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pass provides NATS JetStream abstractions for SmokedMeat.
// In deli terms: The Pass is where the Kitchen places results for pickup.
package pass

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// DefaultConnectTimeout is the default timeout for connecting to NATS.
	DefaultConnectTimeout = 10 * time.Second

	// DefaultReconnectWait is the default wait time between reconnection attempts.
	DefaultReconnectWait = 2 * time.Second

	// DefaultMaxReconnects is the default maximum number of reconnection attempts.
	DefaultMaxReconnects = 60
)

// Subject naming conventions for SmokedMeat.
const (
	// SubjectOrders is the subject for commands from Counter to Brisket.
	// Format: smokedmeat.orders.<agent_id>
	SubjectOrdersPrefix = "smokedmeat.orders"

	// SubjectColeslaw is the subject for responses from Brisket to Counter.
	// Format: smokedmeat.coleslaw.<agent_id>
	SubjectColeslawPrefix = "smokedmeat.coleslaw"

	// SubjectBeacon is the subject for Brisket heartbeats.
	// Format: smokedmeat.beacon.<agent_id>
	SubjectBeaconPrefix = "smokedmeat.beacon"
)

// ClientConfig holds configuration for the NATS client.
type ClientConfig struct {
	URL            string
	Name           string
	ConnectTimeout time.Duration
	ReconnectWait  time.Duration
	MaxReconnects  int
}

// DefaultConfig returns a ClientConfig with sensible defaults.
func DefaultConfig(url string) ClientConfig {
	return ClientConfig{
		URL:            url,
		Name:           "smokedmeat",
		ConnectTimeout: DefaultConnectTimeout,
		ReconnectWait:  DefaultReconnectWait,
		MaxReconnects:  DefaultMaxReconnects,
	}
}

// Client wraps a NATS connection with JetStream support.
type Client struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	config ClientConfig
}

// NewClient creates a new NATS client with the given configuration.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	if config.URL == "" {
		return nil, errors.New("NATS URL is required")
	}

	opts := []nats.Option{
		nats.Name(config.Name),
		nats.Timeout(config.ConnectTimeout),
		nats.ReconnectWait(config.ReconnectWait),
		nats.MaxReconnects(config.MaxReconnects),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				slog.Warn("nats disconnected", "error", err)
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			slog.Info("nats reconnected")
		}),
	}

	nc, err := nats.Connect(config.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	return &Client{
		nc:     nc,
		js:     js,
		config: config,
	}, nil
}

// JetStream returns the underlying JetStream context.
func (c *Client) JetStream() jetstream.JetStream {
	return c.js
}

// Conn returns the underlying NATS connection.
func (c *Client) Conn() *nats.Conn {
	return c.nc
}

// Close closes the NATS connection.
func (c *Client) Close() {
	if c.nc != nil {
		c.nc.Close()
	}
}

// IsConnected returns true if the client is connected to NATS.
func (c *Client) IsConnected() bool {
	return c.nc != nil && c.nc.IsConnected()
}

// EnsureStream creates or updates a JetStream stream.
func (c *Client) EnsureStream(ctx context.Context, config jetstream.StreamConfig) (jetstream.Stream, error) {
	stream, err := c.js.CreateOrUpdateStream(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure stream %s: %w", config.Name, err)
	}
	return stream, nil
}

// OrdersSubject returns the subject for orders to a specific agent.
func OrdersSubject(agentID string) string {
	return fmt.Sprintf("%s.%s", SubjectOrdersPrefix, agentID)
}

// ColeslawSubject returns the subject for responses from a specific agent.
func ColeslawSubject(agentID string) string {
	return fmt.Sprintf("%s.%s", SubjectColeslawPrefix, agentID)
}

// BeaconSubject returns the subject for beacons from a specific agent.
func BeaconSubject(agentID string) string {
	return fmt.Sprintf("%s.%s", SubjectBeaconPrefix, agentID)
}

// DefaultStreamConfig returns the default stream configuration for SmokedMeat.
func DefaultStreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:        "SMOKEDMEAT",
		Description: "SmokedMeat C2 communication stream",
		Subjects: []string{
			SubjectOrdersPrefix + ".>",
			SubjectColeslawPrefix + ".>",
			SubjectBeaconPrefix + ".>",
		},
		Retention:  jetstream.InterestPolicy,
		MaxAge:     24 * time.Hour,
		Storage:    jetstream.FileStorage,
		Replicas:   1,
		Discard:    jetstream.DiscardOld,
		MaxMsgs:    -1,
		MaxBytes:   -1,
		MaxMsgSize: 1024 * 1024, // 1MB max message size
	}
}
