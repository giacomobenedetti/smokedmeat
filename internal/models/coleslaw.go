// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Coleslaw represents the response from a Brisket agent after executing an Order.
// In deli terms: what comes on the side after the order is fulfilled.
type Coleslaw struct {
	// OrderID links this response to the original order.
	OrderID string `json:"order_id"`

	// SessionID links this response to a specific session/campaign.
	SessionID string `json:"session_id"`

	// AgentID identifies the Brisket agent that executed the order.
	AgentID string `json:"agent_id"`

	// Stdout contains base64-encoded standard output from command execution.
	Stdout string `json:"stdout,omitempty"`

	// Stderr contains base64-encoded standard error from command execution.
	Stderr string `json:"stderr,omitempty"`

	// ExitCode is the command's exit code (0 = success).
	ExitCode int `json:"exit_code"`

	// Artifacts lists any files or data collected during execution.
	Artifacts []string `json:"artifacts,omitempty"`

	// Error contains any error message if the command failed.
	Error string `json:"error,omitempty"`

	// CreatedAt is when the response was created.
	CreatedAt time.Time `json:"created_at"`
}

// NewColeslaw creates a new Coleslaw response for an order.
func NewColeslaw(orderID, sessionID, agentID string) *Coleslaw {
	return &Coleslaw{
		OrderID:   orderID,
		SessionID: sessionID,
		AgentID:   agentID,
		CreatedAt: time.Now().UTC(),
	}
}

// SetOutput sets the stdout and stderr from raw bytes.
func (c *Coleslaw) SetOutput(stdout, stderr []byte, exitCode int) {
	if len(stdout) > 0 {
		c.Stdout = base64.StdEncoding.EncodeToString(stdout)
	}
	if len(stderr) > 0 {
		c.Stderr = base64.StdEncoding.EncodeToString(stderr)
	}
	c.ExitCode = exitCode
}

// SetError sets an error message.
func (c *Coleslaw) SetError(err error) {
	if err != nil {
		c.Error = err.Error()
		c.ExitCode = 1
	}
}

// GetStdout returns the decoded stdout.
func (c *Coleslaw) GetStdout() ([]byte, error) {
	if c.Stdout == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(c.Stdout)
}

// GetStderr returns the decoded stderr.
func (c *Coleslaw) GetStderr() ([]byte, error) {
	if c.Stderr == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(c.Stderr)
}

// Success returns true if the command completed without error.
func (c *Coleslaw) Success() bool {
	return c.ExitCode == 0 && c.Error == ""
}

// Marshal serializes the Coleslaw to JSON.
func (c *Coleslaw) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalColeslaw deserializes a Coleslaw from JSON.
func UnmarshalColeslaw(data []byte) (*Coleslaw, error) {
	var c Coleslaw
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
