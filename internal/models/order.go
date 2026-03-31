// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package models contains domain models for SmokedMeat communication.
package models

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// OrderStatus represents the current state of an order.
type OrderStatus string

const (
	OrderStatusPending   OrderStatus = "pending"
	OrderStatusDelivered OrderStatus = "delivered"
	OrderStatusExecuting OrderStatus = "executing"
	OrderStatusCompleted OrderStatus = "completed"
	OrderStatusFailed    OrderStatus = "failed"
)

// Order represents a command sent from the Counter to a Brisket agent.
// In deli terms: this is what the customer orders from the menu.
type Order struct {
	// OrderID uniquely identifies this order.
	OrderID string `json:"order_id"`

	// SessionID links this order to a specific session/campaign.
	SessionID string `json:"session_id"`

	// AgentID identifies the target Brisket agent.
	AgentID string `json:"agent_id"`

	// OperatorID identifies which operator sent this order (for multi-operator support).
	OperatorID string `json:"operator_id,omitempty"`

	// OperatorName is the human-readable operator name (for display/audit).
	OperatorName string `json:"operator_name,omitempty"`

	// Command is the operation to execute (e.g., "exec", "upload", "download").
	Command string `json:"command"`

	// Args contains command-specific arguments.
	Args []string `json:"args,omitempty"`

	// Status tracks the order's current state.
	Status OrderStatus `json:"status"`

	// CreatedAt is when the order was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the order was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// NewOrder creates a new Order with a generated ID and pending status.
func NewOrder(sessionID, agentID, command string, args []string) *Order {
	now := time.Now().UTC()
	return &Order{
		OrderID:   generateID(),
		SessionID: sessionID,
		AgentID:   agentID,
		Command:   command,
		Args:      args,
		Status:    OrderStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Marshal serializes the Order to JSON.
func (o *Order) Marshal() ([]byte, error) {
	return json.Marshal(o)
}

// UnmarshalOrder deserializes an Order from JSON.
func UnmarshalOrder(data []byte) (*Order, error) {
	var o Order
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// MarkDelivered updates the order status to delivered.
func (o *Order) MarkDelivered() {
	o.Status = OrderStatusDelivered
	o.UpdatedAt = time.Now().UTC()
}

// MarkExecuting updates the order status to executing.
func (o *Order) MarkExecuting() {
	o.Status = OrderStatusExecuting
	o.UpdatedAt = time.Now().UTC()
}

// MarkCompleted updates the order status to completed.
func (o *Order) MarkCompleted() {
	o.Status = OrderStatusCompleted
	o.UpdatedAt = time.Now().UTC()
}

// MarkFailed updates the order status to failed.
func (o *Order) MarkFailed() {
	o.Status = OrderStatusFailed
	o.UpdatedAt = time.Now().UTC()
}

// generateID creates a random 16-character hex ID.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return hex.EncodeToString([]byte(time.Now().UTC().String())[:8])
	}
	return hex.EncodeToString(b)
}
