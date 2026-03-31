// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package counter implements the Counter TUI operator interface.
package counter

import (
	"time"
)

// Beacon represents an agent heartbeat message.
type Beacon struct {
	AgentID       string     `json:"agent_id"`
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Arch          string     `json:"arch"`
	Timestamp     time.Time  `json:"timestamp"`
	DwellDeadline *time.Time `json:"dwell_deadline,omitempty"`
	CallbackID    string     `json:"callback_id,omitempty"`
	CallbackMode  string     `json:"callback_mode,omitempty"`
}
