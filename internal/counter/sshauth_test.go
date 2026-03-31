// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSSHAuthClient(t *testing.T) {
	client := NewSSHAuthClient(SSHAuthConfig{
		KitchenURL: "https://kitchen.example.com",
		Operator:   "alice",
		KeyComment: "alice@laptop",
	})

	assert.NotNil(t, client)
	assert.Equal(t, "https://kitchen.example.com", client.kitchenURL)
	assert.Equal(t, "alice", client.operator)
	assert.Equal(t, "alice@laptop", client.keyComment)
}

func TestNewSSHAuthClientTrimsTrailingSlash(t *testing.T) {
	client := NewSSHAuthClient(SSHAuthConfig{
		KitchenURL: "https://kitchen.example.com/",
		Operator:   "bob",
	})

	assert.Equal(t, "https://kitchen.example.com", client.kitchenURL)
}

// Note: Full integration tests for SSH auth require either:
// 1. A real SSH agent with keys loaded
// 2. A mock SSH agent (complex to set up)
// 3. Integration test with real Kitchen server
//
// The auth_test.go in internal/kitchen/auth/ tests the server-side logic.
// This file tests client construction and configuration.
