// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrder_NewOrder(t *testing.T) {
	order := NewOrder("session-1", "agent-1", "exec", []string{"ls", "-la"})

	assert.NotEmpty(t, order.OrderID)
	assert.Equal(t, "session-1", order.SessionID)
	assert.Equal(t, "agent-1", order.AgentID)
	assert.Equal(t, "exec", order.Command)
	assert.Equal(t, []string{"ls", "-la"}, order.Args)
	assert.Equal(t, OrderStatusPending, order.Status)
	assert.False(t, order.CreatedAt.IsZero())
}

func TestOrder_StatusTransitions(t *testing.T) {
	order := NewOrder("s1", "a1", "exec", nil)
	originalTime := order.UpdatedAt

	time.Sleep(time.Millisecond)

	order.MarkDelivered()
	assert.Equal(t, OrderStatusDelivered, order.Status)
	assert.True(t, order.UpdatedAt.After(originalTime))

	order.MarkExecuting()
	assert.Equal(t, OrderStatusExecuting, order.Status)

	order.MarkCompleted()
	assert.Equal(t, OrderStatusCompleted, order.Status)
}

func TestOrder_MarshalUnmarshal(t *testing.T) {
	order := NewOrder("session-1", "agent-1", "exec", []string{"ls", "-la"})

	data, err := order.Marshal()
	require.NoError(t, err)

	decoded, err := UnmarshalOrder(data)
	require.NoError(t, err)

	assert.Equal(t, order.OrderID, decoded.OrderID)
	assert.Equal(t, order.SessionID, decoded.SessionID)
	assert.Equal(t, order.AgentID, decoded.AgentID)
	assert.Equal(t, order.Command, decoded.Command)
	assert.Equal(t, order.Args, decoded.Args)
	assert.Equal(t, order.Status, decoded.Status)
}

func TestColeslaw_NewColeslaw(t *testing.T) {
	coleslaw := NewColeslaw("order-1", "session-1", "agent-1")

	assert.Equal(t, "order-1", coleslaw.OrderID)
	assert.Equal(t, "session-1", coleslaw.SessionID)
	assert.Equal(t, "agent-1", coleslaw.AgentID)
	assert.False(t, coleslaw.CreatedAt.IsZero())
}

func TestColeslaw_SetOutput(t *testing.T) {
	coleslaw := NewColeslaw("o1", "s1", "a1")

	stdout := []byte("hello world")
	stderr := []byte("warning: something")
	coleslaw.SetOutput(stdout, stderr, 0)

	assert.NotEmpty(t, coleslaw.Stdout)
	assert.NotEmpty(t, coleslaw.Stderr)
	assert.Equal(t, 0, coleslaw.ExitCode)
	assert.True(t, coleslaw.Success())

	decodedStdout, err := coleslaw.GetStdout()
	require.NoError(t, err)
	assert.Equal(t, stdout, decodedStdout)

	decodedStderr, err := coleslaw.GetStderr()
	require.NoError(t, err)
	assert.Equal(t, stderr, decodedStderr)
}

func TestColeslaw_SetError(t *testing.T) {
	coleslaw := NewColeslaw("o1", "s1", "a1")

	coleslaw.SetError(assert.AnError)

	assert.Equal(t, "assert.AnError general error for testing", coleslaw.Error)
	assert.Equal(t, 1, coleslaw.ExitCode)
	assert.False(t, coleslaw.Success())
}

func TestColeslaw_MarshalUnmarshal(t *testing.T) {
	coleslaw := NewColeslaw("order-1", "session-1", "agent-1")
	coleslaw.SetOutput([]byte("output"), nil, 0)

	data, err := coleslaw.Marshal()
	require.NoError(t, err)

	decoded, err := UnmarshalColeslaw(data)
	require.NoError(t, err)

	assert.Equal(t, coleslaw.OrderID, decoded.OrderID)
	assert.Equal(t, coleslaw.Stdout, decoded.Stdout)
	assert.Equal(t, coleslaw.ExitCode, decoded.ExitCode)
}
