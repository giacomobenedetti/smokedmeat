// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModel_Update_KitchenConnected(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(KitchenConnectedMsg{})

	model := result.(Model)
	assert.True(t, model.connected)
	assert.Equal(t, "connected", model.connectionState)
}

func TestModel_Update_KitchenDisconnected(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.connected = true
	m.connectionState = "connected"

	result, _ := m.Update(KitchenDisconnectedMsg{})

	model := result.(Model)
	assert.False(t, model.connected)
	assert.Equal(t, "disconnected", model.connectionState)
}

func TestModel_Update_KitchenError(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(KitchenErrorMsg{Err: errors.New("connection refused")})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "error", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "connection refused")
}
