// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pass

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Configuration Tests
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig("nats://localhost:4222")

	assert.Equal(t, "nats://localhost:4222", config.URL)
	assert.Equal(t, "smokedmeat", config.Name)
	assert.Equal(t, DefaultConnectTimeout, config.ConnectTimeout)
	assert.Equal(t, DefaultReconnectWait, config.ReconnectWait)
	assert.Equal(t, DefaultMaxReconnects, config.MaxReconnects)
}

func TestDefaultConfig_EmptyURL(t *testing.T) {
	config := DefaultConfig("")

	assert.Empty(t, config.URL)
	// Other defaults should still be set
	assert.Equal(t, "smokedmeat", config.Name)
}

// =============================================================================
// Subject Formatting Tests
// =============================================================================

func TestOrdersSubject(t *testing.T) {
	tests := []struct {
		agentID  string
		expected string
	}{
		{"agent-123", "smokedmeat.orders.agent-123"},
		{"brisket-abc", "smokedmeat.orders.brisket-abc"},
		{"", "smokedmeat.orders."},
	}

	for _, tt := range tests {
		t.Run(tt.agentID, func(t *testing.T) {
			result := OrdersSubject(tt.agentID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestColeslawSubject(t *testing.T) {
	tests := []struct {
		agentID  string
		expected string
	}{
		{"agent-123", "smokedmeat.coleslaw.agent-123"},
		{"brisket-xyz", "smokedmeat.coleslaw.brisket-xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.agentID, func(t *testing.T) {
			result := ColeslawSubject(tt.agentID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBeaconSubject(t *testing.T) {
	tests := []struct {
		agentID  string
		expected string
	}{
		{"agent-123", "smokedmeat.beacon.agent-123"},
		{"brisket-foo", "smokedmeat.beacon.brisket-foo"},
	}

	for _, tt := range tests {
		t.Run(tt.agentID, func(t *testing.T) {
			result := BeaconSubject(tt.agentID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Stream Configuration Tests
// =============================================================================

func TestDefaultStreamConfig(t *testing.T) {
	config := DefaultStreamConfig()

	assert.Equal(t, "SMOKEDMEAT", config.Name)
	assert.NotEmpty(t, config.Description)

	// Check subjects include all prefixes
	assert.Contains(t, config.Subjects, SubjectOrdersPrefix+".>")
	assert.Contains(t, config.Subjects, SubjectColeslawPrefix+".>")
	assert.Contains(t, config.Subjects, SubjectBeaconPrefix+".>")

	// Check retention policy
	assert.Equal(t, jetstream.InterestPolicy, config.Retention)

	// Check storage type
	assert.Equal(t, jetstream.FileStorage, config.Storage)

	// Check max message size (1MB)
	assert.Equal(t, int32(1024*1024), config.MaxMsgSize)

	// Check retention period (24 hours)
	assert.Equal(t, 24*time.Hour, config.MaxAge)
}

// =============================================================================
// Consumer Configuration Tests
// =============================================================================

// =============================================================================
// Constants Tests
// =============================================================================

func TestConstants(t *testing.T) {
	// Verify timeout constants are reasonable
	assert.Equal(t, 10*time.Second, DefaultConnectTimeout)
	assert.Equal(t, 2*time.Second, DefaultReconnectWait)
	assert.Equal(t, 60, DefaultMaxReconnects)

	// Verify subject prefixes are set correctly
	assert.Equal(t, "smokedmeat.orders", SubjectOrdersPrefix)
	assert.Equal(t, "smokedmeat.coleslaw", SubjectColeslawPrefix)
	assert.Equal(t, "smokedmeat.beacon", SubjectBeaconPrefix)
}

// =============================================================================
// Client Tests (without NATS connection)
// =============================================================================

func TestNewClient_RequiresURL(t *testing.T) {
	config := ClientConfig{
		URL: "",
	}

	client, err := NewClient(t.Context(), config)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "NATS URL is required")
}

func TestNewClient_FailsOnBadURL(t *testing.T) {
	config := ClientConfig{
		URL:            "nats://localhost:59999", // Unlikely to be running
		ConnectTimeout: 100 * time.Millisecond,
	}

	client, err := NewClient(t.Context(), config)

	assert.Error(t, err)
	assert.Nil(t, client)
}

func TestPublisher_NewPublisher(t *testing.T) {
	// Can create a publisher with nil client (will fail on use, but constructor works)
	pub := NewPublisher(nil)
	assert.NotNil(t, pub)
}

// =============================================================================
// Timeout Constants Tests
// =============================================================================

func TestDefaultCallbackTimeout(t *testing.T) {
	// Verify default callback timeout is set to a reasonable value
	assert.Equal(t, 30*time.Second, DefaultCallbackTimeout)
	assert.Greater(t, DefaultCallbackTimeout, time.Duration(0))
}
