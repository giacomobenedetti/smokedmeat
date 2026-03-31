// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// SessionRegistry Tests
// =============================================================================

func TestNewSessionRegistry(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())
	assert.NotNil(t, registry)
	assert.NotNil(t, registry.sessions)
	assert.NotNil(t, registry.agents)
	assert.NotNil(t, registry.operators)
}

func TestSessionRegistry_GetOrCreateSession(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	// Create new session
	session1 := registry.GetOrCreateSession("session-1")
	require.NotNil(t, session1)
	assert.Equal(t, "session-1", session1.ID)
	assert.False(t, session1.CreatedAt.IsZero())

	// Get existing session
	session2 := registry.GetOrCreateSession("session-1")
	assert.Equal(t, session1, session2)
}

func TestSessionRegistry_GetSession(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	// Non-existent session
	session := registry.GetSession("nonexistent")
	assert.Nil(t, session)

	// Create and get
	registry.GetOrCreateSession("session-1")
	session = registry.GetSession("session-1")
	require.NotNil(t, session)
	assert.Equal(t, "session-1", session.ID)
}

func TestSessionRegistry_ListSessions(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	registry.GetOrCreateSession("session-1")
	registry.GetOrCreateSession("session-2")

	sessions := registry.ListSessions()
	assert.Len(t, sessions, 2)
}

// =============================================================================
// Operator Tests
// =============================================================================

func TestSessionRegistry_RegisterOperator(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	op := Operator{
		ID:        "op-1",
		Name:      "Alice",
		SessionID: "session-1",
	}

	registry.RegisterOperator(op)

	// Check operator exists
	retrieved := registry.GetOperator("op-1")
	require.NotNil(t, retrieved)
	assert.Equal(t, "Alice", retrieved.Name)
	assert.Equal(t, "session-1", retrieved.SessionID)
	assert.False(t, retrieved.ConnectedAt.IsZero())

	// Check operator added to session
	session := registry.GetSession("session-1")
	require.NotNil(t, session)
	assert.Len(t, session.Operators, 1)
	assert.Equal(t, "op-1", session.Operators[0].ID)
}

func TestSessionRegistry_RegisterOperator_Update(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	// Register first time
	op := Operator{
		ID:        "op-1",
		Name:      "Alice",
		SessionID: "session-1",
	}
	registry.RegisterOperator(op)

	// Update
	op.Name = "Alice Updated"
	registry.RegisterOperator(op)

	// Should still only have one operator
	session := registry.GetSession("session-1")
	assert.Len(t, session.Operators, 1)
	assert.Equal(t, "Alice Updated", session.Operators[0].Name)
}

func TestSessionRegistry_UnregisterOperator(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	op := Operator{
		ID:        "op-1",
		Name:      "Alice",
		SessionID: "session-1",
	}
	registry.RegisterOperator(op)

	// Unregister
	registry.UnregisterOperator("op-1")

	// Should be gone
	assert.Nil(t, registry.GetOperator("op-1"))

	// Should be removed from session
	session := registry.GetSession("session-1")
	assert.Len(t, session.Operators, 0)
}

func TestSessionRegistry_UnregisterOperator_NonExistent(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	// Should not panic
	registry.UnregisterOperator("nonexistent")
}

func TestSessionRegistry_ListOperators(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	registry.RegisterOperator(Operator{ID: "op-1", SessionID: "session-1"})
	registry.RegisterOperator(Operator{ID: "op-2", SessionID: "session-1"})
	registry.RegisterOperator(Operator{ID: "op-3", SessionID: "session-2"})

	// List for session-1
	operators := registry.ListOperators("session-1")
	assert.Len(t, operators, 2)

	// List for session-2
	operators = registry.ListOperators("session-2")
	assert.Len(t, operators, 1)

	// List for non-existent
	operators = registry.ListOperators("nonexistent")
	assert.Nil(t, operators)
}

// =============================================================================
// Agent Tests
// =============================================================================

func TestSessionRegistry_UpdateAgentBeacon(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	registry.UpdateAgentBeacon("agent-1", "session-1", "host-1", "linux", "amd64")

	// Check agent exists
	agent := registry.GetAgent("agent-1")
	require.NotNil(t, agent)
	assert.Equal(t, "agent-1", agent.AgentID)
	assert.Equal(t, "session-1", agent.SessionID)
	assert.Equal(t, "host-1", agent.Hostname)
	assert.Equal(t, "linux", agent.OS)
	assert.Equal(t, "amd64", agent.Arch)
	assert.True(t, agent.IsOnline)
	assert.False(t, agent.FirstSeen.IsZero())
	assert.False(t, agent.LastSeen.IsZero())

	// Check agent added to session
	session := registry.GetSession("session-1")
	require.NotNil(t, session)
	assert.Len(t, session.Agents, 1)
}

func TestSessionRegistry_UpdateAgentBeacon_Update(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	// First beacon
	registry.UpdateAgentBeacon("agent-1", "session-1", "host-1", "linux", "amd64")
	firstSeen := registry.GetAgent("agent-1").FirstSeen

	// Second beacon (update)
	time.Sleep(10 * time.Millisecond)
	registry.UpdateAgentBeacon("agent-1", "session-1", "host-1-updated", "linux", "amd64")

	agent := registry.GetAgent("agent-1")
	assert.Equal(t, "host-1-updated", agent.Hostname)
	assert.Equal(t, firstSeen, agent.FirstSeen) // FirstSeen should not change
	assert.True(t, agent.LastSeen.After(firstSeen))
}

func TestSessionRegistry_ListAgents(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	registry.UpdateAgentBeacon("agent-1", "session-1", "host-1", "linux", "amd64")
	registry.UpdateAgentBeacon("agent-2", "session-1", "host-2", "windows", "amd64")
	registry.UpdateAgentBeacon("agent-3", "session-2", "host-3", "darwin", "arm64")

	// List for session-1
	agents := registry.ListAgents("session-1")
	assert.Len(t, agents, 2)

	// List for session-2
	agents = registry.ListAgents("session-2")
	assert.Len(t, agents, 1)

	// List for non-existent
	agents = registry.ListAgents("nonexistent")
	assert.Nil(t, agents)
}

func TestSessionRegistry_UpdateAgentOnlineStatus(t *testing.T) {
	config := DefaultSessionRegistryConfig()
	config.AgentTimeout = 50 * time.Millisecond
	registry := NewSessionRegistry(config)

	registry.UpdateAgentBeacon("agent-1", "session-1", "host-1", "linux", "amd64")

	// Should be online initially
	assert.True(t, registry.GetAgent("agent-1").IsOnline)

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	// Update status
	registry.UpdateAgentOnlineStatus()

	// Should be offline now
	assert.False(t, registry.GetAgent("agent-1").IsOnline)
}

// =============================================================================
// Stats Tests
// =============================================================================

func TestSessionRegistry_Stats(t *testing.T) {
	registry := NewSessionRegistry(DefaultSessionRegistryConfig())

	registry.GetOrCreateSession("session-1")
	registry.RegisterOperator(Operator{ID: "op-1", SessionID: "session-1"})
	registry.UpdateAgentBeacon("agent-1", "session-1", "host-1", "linux", "amd64")
	registry.UpdateAgentBeacon("agent-2", "session-1", "host-2", "linux", "amd64")

	stats := registry.Stats()

	assert.Equal(t, 1, stats["sessions"])
	assert.Equal(t, 1, stats["operators"])
	assert.Equal(t, 2, stats["agents_total"])
	assert.Equal(t, 2, stats["agents_online"])
	assert.Equal(t, 0, stats["agents_offline"])
}

// =============================================================================
// Operator Struct Tests
// =============================================================================

func TestOperator_Fields(t *testing.T) {
	now := time.Now()
	op := Operator{
		ID:          "op-1",
		Name:        "Alice",
		SessionID:   "session-1",
		ConnectedAt: now,
		LastSeen:    now,
		RemoteAddr:  "192.168.1.100",
	}

	assert.Equal(t, "op-1", op.ID)
	assert.Equal(t, "Alice", op.Name)
	assert.Equal(t, "session-1", op.SessionID)
	assert.Equal(t, now, op.ConnectedAt)
	assert.Equal(t, now, op.LastSeen)
	assert.Equal(t, "192.168.1.100", op.RemoteAddr)
}

// =============================================================================
// AgentState Struct Tests
// =============================================================================

func TestAgentState_Fields(t *testing.T) {
	now := time.Now()
	agent := AgentState{
		AgentID:       "agent-1",
		SessionID:     "session-1",
		Hostname:      "host-1",
		OS:            "linux",
		Arch:          "amd64",
		FirstSeen:     now,
		LastSeen:      now,
		IsOnline:      true,
		PendingOrders: 5,
	}

	assert.Equal(t, "agent-1", agent.AgentID)
	assert.Equal(t, "session-1", agent.SessionID)
	assert.Equal(t, "host-1", agent.Hostname)
	assert.Equal(t, "linux", agent.OS)
	assert.Equal(t, "amd64", agent.Arch)
	assert.Equal(t, now, agent.FirstSeen)
	assert.Equal(t, now, agent.LastSeen)
	assert.True(t, agent.IsOnline)
	assert.Equal(t, 5, agent.PendingOrders)
}

// =============================================================================
// Session Struct Tests
// =============================================================================

func TestSession_Fields(t *testing.T) {
	now := time.Now()
	session := Session{
		ID:          "session-1",
		Target:      "acme/api",
		ThreatModel: "supply-chain",
		CreatedAt:   now,
		Operators:   []Operator{{ID: "op-1"}},
		Agents:      []AgentState{{AgentID: "agent-1"}},
	}

	assert.Equal(t, "session-1", session.ID)
	assert.Equal(t, "acme/api", session.Target)
	assert.Equal(t, "supply-chain", session.ThreatModel)
	assert.Equal(t, now, session.CreatedAt)
	assert.Len(t, session.Operators, 1)
	assert.Len(t, session.Agents, 1)
}
