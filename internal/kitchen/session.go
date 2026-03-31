// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"sync"
	"time"
)

// Operator represents a connected Counter instance.
type Operator struct {
	// ID is a unique identifier for this operator.
	ID string `json:"id"`

	// Name is the human-readable operator name.
	Name string `json:"name,omitempty"`

	// SessionID is the session this operator is connected to.
	SessionID string `json:"session_id"`

	// ConnectedAt is when the operator connected.
	ConnectedAt time.Time `json:"connected_at"`

	// LastSeen is the last heartbeat from this operator.
	LastSeen time.Time `json:"last_seen"`

	// RemoteAddr is the operator's IP address.
	RemoteAddr string `json:"remote_addr,omitempty"`
}

// AgentState represents the current state of an agent.
type AgentState struct {
	// AgentID is the unique identifier for this agent.
	AgentID string `json:"agent_id"`

	// SessionID is the session this agent belongs to.
	SessionID string `json:"session_id"`

	// Hostname is the agent's reported hostname.
	Hostname string `json:"hostname"`

	// OS is the agent's operating system.
	OS string `json:"os"`

	// Arch is the agent's architecture.
	Arch string `json:"arch"`

	// FirstSeen is when this agent first connected.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is the last beacon from this agent.
	LastSeen time.Time `json:"last_seen"`

	// IsOnline indicates if the agent is currently online.
	IsOnline bool `json:"is_online"`

	// PendingOrders is the count of orders waiting for this agent.
	PendingOrders int `json:"pending_orders"`

	// DwellDeadline is when the dwell period expires (nil = express mode).
	DwellDeadline *time.Time `json:"dwell_deadline,omitempty"`
}

// Session represents an active session with connected operators and agents.
type Session struct {
	// ID is the unique session identifier.
	ID string `json:"id"`

	// Target is the target of this session (e.g., "acme/api" or "acme" org).
	Target string `json:"target,omitempty"`

	// ThreatModel is the threat model being demonstrated.
	ThreatModel string `json:"threat_model,omitempty"`

	// CreatedAt is when the session was created.
	CreatedAt time.Time `json:"created_at"`

	// Operators is the list of connected operators.
	Operators []Operator `json:"operators"`

	// Agents is the list of connected agents.
	Agents []AgentState `json:"agents"`
}

// SessionRegistry tracks active sessions, operators, and agents.
type SessionRegistry struct {
	mu sync.RWMutex

	// sessions maps session ID to session state
	sessions map[string]*Session

	// agents maps agent ID to agent state
	agents map[string]*AgentState

	// operators maps operator ID to operator state
	operators map[string]*Operator

	// sessionDwellDeadlines maps session ID to dwell deadline (set when stager triggers)
	sessionDwellDeadlines map[string]*time.Time

	// agentTimeout is how long before an agent is considered offline
	agentTimeout time.Duration

	// operatorTimeout is how long before an operator is considered disconnected
	operatorTimeout time.Duration
}

// SessionRegistryConfig holds configuration for the session registry.
type SessionRegistryConfig struct {
	AgentTimeout    time.Duration
	OperatorTimeout time.Duration
}

// DefaultSessionRegistryConfig returns default configuration.
func DefaultSessionRegistryConfig() SessionRegistryConfig {
	return SessionRegistryConfig{
		AgentTimeout:    1 * time.Minute,
		OperatorTimeout: 5 * time.Minute,
	}
}

// NewSessionRegistry creates a new session registry.
func NewSessionRegistry(config SessionRegistryConfig) *SessionRegistry {
	return &SessionRegistry{
		sessions:              make(map[string]*Session),
		agents:                make(map[string]*AgentState),
		operators:             make(map[string]*Operator),
		sessionDwellDeadlines: make(map[string]*time.Time),
		agentTimeout:          config.AgentTimeout,
		operatorTimeout:       config.OperatorTimeout,
	}
}

// SetSessionDwellDeadline sets the dwell deadline for a session (called when stager triggers).
func (r *SessionRegistry) SetSessionDwellDeadline(sessionID string, deadline *time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessionDwellDeadlines[sessionID] = deadline
}

// GetSessionDwellDeadline returns the dwell deadline for a session.
func (r *SessionRegistry) GetSessionDwellDeadline(sessionID string) *time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessionDwellDeadlines[sessionID]
}

// GetOrCreateSession returns an existing session or creates a new one.
func (r *SessionRegistry) GetOrCreateSession(sessionID string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	if session, exists := r.sessions[sessionID]; exists {
		return session
	}

	session := &Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
		Operators: []Operator{},
		Agents:    []AgentState{},
	}
	r.sessions[sessionID] = session
	return session
}

// UpdateAgentBeacon updates an agent's state from a beacon.
func (r *SessionRegistry) UpdateAgentBeacon(agentID, sessionID, hostname, os, arch string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	agent, exists := r.agents[agentID]
	if !exists {
		agent = &AgentState{
			AgentID:   agentID,
			SessionID: sessionID,
			FirstSeen: now,
		}
		r.agents[agentID] = agent
	}

	agent.Hostname = hostname
	agent.OS = os
	agent.Arch = arch
	agent.LastSeen = now
	agent.IsOnline = true
	agent.SessionID = sessionID
	if deadline := r.sessionDwellDeadlines[sessionID]; deadline != nil && agent.DwellDeadline == nil {
		agent.DwellDeadline = deadline
	}

	session := r.sessions[sessionID]
	if session == nil {
		session = &Session{
			ID:        sessionID,
			CreatedAt: now,
			Operators: []Operator{},
			Agents:    []AgentState{},
		}
		r.sessions[sessionID] = session
	}

	found := false
	for i, existing := range session.Agents {
		if existing.AgentID == agentID {
			session.Agents[i] = *agent
			found = true
			break
		}
	}
	if !found {
		session.Agents = append(session.Agents, *agent)
	}
}

// GetAgent returns an agent by ID.
func (r *SessionRegistry) GetAgent(agentID string) *AgentState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.agents[agentID]
}

// UpdateAgentOnlineStatus marks agents as offline if they haven't sent a beacon recently.
func (r *SessionRegistry) UpdateAgentOnlineStatus() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.agentTimeout)

	for _, agent := range r.agents {
		if agent.LastSeen.Before(cutoff) {
			agent.IsOnline = false
		}
	}

	for _, session := range r.sessions {
		for i := range session.Agents {
			agent := r.agents[session.Agents[i].AgentID]
			if agent != nil {
				session.Agents[i].IsOnline = agent.IsOnline
			}
		}
	}
}

// GetSession returns a session by ID, or nil if not found.
func (r *SessionRegistry) GetSession(sessionID string) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[sessionID]
}

// ListSessions returns all sessions.
func (r *SessionRegistry) ListSessions() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sessions := make([]*Session, 0, len(r.sessions))
	for _, session := range r.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// RegisterOperator registers a new operator.
func (r *SessionRegistry) RegisterOperator(op Operator) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if op.ConnectedAt.IsZero() {
		op.ConnectedAt = now
	}
	op.LastSeen = now

	r.operators[op.ID] = &op

	session := r.sessions[op.SessionID]
	if session == nil {
		session = &Session{
			ID:        op.SessionID,
			CreatedAt: now,
			Operators: []Operator{},
			Agents:    []AgentState{},
		}
		r.sessions[op.SessionID] = session
	}

	found := false
	for i, existing := range session.Operators {
		if existing.ID == op.ID {
			session.Operators[i] = op
			found = true
			break
		}
	}
	if !found {
		session.Operators = append(session.Operators, op)
	}
}

// GetOperator returns an operator by ID.
func (r *SessionRegistry) GetOperator(operatorID string) *Operator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.operators[operatorID]
}

// UnregisterOperator removes an operator.
func (r *SessionRegistry) UnregisterOperator(operatorID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	op := r.operators[operatorID]
	if op == nil {
		return
	}

	delete(r.operators, operatorID)

	if session := r.sessions[op.SessionID]; session != nil {
		for i, existing := range session.Operators {
			if existing.ID == operatorID {
				session.Operators = append(session.Operators[:i], session.Operators[i+1:]...)
				break
			}
		}
	}
}

// ListOperators returns all operators for a session.
func (r *SessionRegistry) ListOperators(sessionID string) []Operator {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session := r.sessions[sessionID]
	if session == nil {
		return nil
	}
	return session.Operators
}

// ListAgents returns all agents for a session.
func (r *SessionRegistry) ListAgents(sessionID string) []AgentState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session := r.sessions[sessionID]
	if session == nil {
		return nil
	}
	return session.Agents
}

// Stats returns registry statistics.
func (r *SessionRegistry) Stats() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	online := 0
	offline := 0
	for _, agent := range r.agents {
		if agent.IsOnline {
			online++
		} else {
			offline++
		}
	}

	return map[string]int{
		"sessions":       len(r.sessions),
		"operators":      len(r.operators),
		"agents_total":   len(r.agents),
		"agents_online":  online,
		"agents_offline": offline,
	}
}
