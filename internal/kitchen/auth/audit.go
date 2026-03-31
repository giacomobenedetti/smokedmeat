// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"log/slog"
	"net/http"
	"time"
)

type SecurityEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	ClientIP    string    `json:"client_ip"`
	Path        string    `json:"path"`
	Method      string    `json:"method"`
	Principal   string    `json:"principal"`
	PrincipalID string    `json:"principal_id,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	Reason      string    `json:"reason"`
	UserAgent   string    `json:"user_agent,omitempty"`
}

const (
	EventAuthFailure       = "auth_failure"
	EventAuthzFailure      = "authz_failure"
	EventStagerNotFound    = "stager_not_found"
	EventStagerExpired     = "stager_expired"
	EventAgentTokenInvalid = "agent_token_invalid"
	EventSessionMismatch   = "session_mismatch"

	PrincipalOperator = "operator"
	PrincipalAgent    = "agent"
	PrincipalStager   = "stager"
	PrincipalUnknown  = "unknown"
)

type AuditLogger interface {
	LogSecurityEvent(event SecurityEvent)
}

type StructuredAuditLogger struct {
	logger *slog.Logger
}

func NewStructuredAuditLogger(logger *slog.Logger) *StructuredAuditLogger {
	return &StructuredAuditLogger{logger: logger}
}

func (l *StructuredAuditLogger) LogSecurityEvent(event SecurityEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	l.logger.Warn("security_event",
		"event_type", event.EventType,
		"client_ip", event.ClientIP,
		"path", event.Path,
		"method", event.Method,
		"principal", event.Principal,
		"principal_id", event.PrincipalID,
		"session_id", event.SessionID,
		"reason", event.Reason,
		"user_agent", event.UserAgent,
	)
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

func NewSecurityEventFromRequest(r *http.Request, eventType, principal, reason string) SecurityEvent {
	return SecurityEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		ClientIP:  extractClientIP(r),
		Path:      r.URL.Path,
		Method:    r.Method,
		Principal: principal,
		Reason:    reason,
		UserAgent: r.UserAgent(),
	}
}
