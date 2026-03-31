// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBeacon_JSONMarshal(t *testing.T) {
	timestamp := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	beacon := Beacon{
		AgentID:   "agent-123",
		Hostname:  "test-host",
		OS:        "linux",
		Arch:      "amd64",
		Timestamp: timestamp,
	}

	data, err := json.Marshal(beacon)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "agent-123", parsed["agent_id"])
	assert.Equal(t, "test-host", parsed["hostname"])
	assert.Equal(t, "linux", parsed["os"])
	assert.Equal(t, "amd64", parsed["arch"])
}

func TestBeacon_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"agent_id": "agent-456",
		"hostname": "prod-server",
		"os": "darwin",
		"arch": "arm64",
		"timestamp": "2024-01-15T10:30:00Z"
	}`

	var beacon Beacon
	err := json.Unmarshal([]byte(jsonData), &beacon)
	require.NoError(t, err)

	assert.Equal(t, "agent-456", beacon.AgentID)
	assert.Equal(t, "prod-server", beacon.Hostname)
	assert.Equal(t, "darwin", beacon.OS)
	assert.Equal(t, "arm64", beacon.Arch)
	assert.False(t, beacon.Timestamp.IsZero())
}

func TestBeacon_JSONUnmarshal_PartialData(t *testing.T) {
	jsonData := `{"agent_id": "minimal-agent"}`

	var beacon Beacon
	err := json.Unmarshal([]byte(jsonData), &beacon)
	require.NoError(t, err)

	assert.Equal(t, "minimal-agent", beacon.AgentID)
	assert.Empty(t, beacon.Hostname)
	assert.Empty(t, beacon.OS)
	assert.Empty(t, beacon.Arch)
	assert.True(t, beacon.Timestamp.IsZero())
}

func TestBeacon_JSONUnmarshal_EmptyObject(t *testing.T) {
	jsonData := `{}`

	var beacon Beacon
	err := json.Unmarshal([]byte(jsonData), &beacon)
	require.NoError(t, err)

	assert.Empty(t, beacon.AgentID)
}

func TestBeacon_JSONRoundTrip(t *testing.T) {
	original := Beacon{
		AgentID:   "roundtrip-agent",
		Hostname:  "roundtrip-host",
		OS:        "windows",
		Arch:      "amd64",
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Beacon
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.AgentID, decoded.AgentID)
	assert.Equal(t, original.Hostname, decoded.Hostname)
	assert.Equal(t, original.OS, decoded.OS)
	assert.Equal(t, original.Arch, decoded.Arch)
	assert.True(t, original.Timestamp.Equal(decoded.Timestamp))
}
