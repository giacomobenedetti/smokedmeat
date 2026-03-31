// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRelationship(t *testing.T) {
	rel := NewRelationship(RelContains)

	assert.Equal(t, RelContains, rel.Type)
	assert.NotNil(t, rel.Properties)
	assert.Empty(t, rel.Properties)
}

func TestRelationship_WithProperty(t *testing.T) {
	rel := NewRelationship(RelExposes).
		WithProperty("job", "build").
		WithProperty("step", "checkout")

	assert.Equal(t, RelExposes, rel.Type)
	assert.Equal(t, "build", rel.Properties["job"])
	assert.Equal(t, "checkout", rel.Properties["step"])
}

func TestRelationship_WithProperty_NilProperties(t *testing.T) {
	rel := Relationship{Type: RelContains}

	// Should not panic and should initialize properties
	rel = rel.WithProperty("key", "value")
	assert.Equal(t, "value", rel.Properties["key"])
}

func TestNewEdge(t *testing.T) {
	rel := Contains()
	edge := NewEdge("from-id", "to-id", rel)

	assert.Equal(t, "from-id", edge.From)
	assert.Equal(t, "to-id", edge.To)
	assert.Equal(t, RelContains, edge.Relationship.Type)
}

func TestContains(t *testing.T) {
	rel := Contains()

	assert.Equal(t, RelContains, rel.Type)
	assert.NotNil(t, rel.Properties)
}

func TestExposes(t *testing.T) {
	rel := Exposes("deploy", "checkout")

	assert.Equal(t, RelExposes, rel.Type)
	assert.Equal(t, "deploy", rel.Properties["job"])
	assert.Equal(t, "checkout", rel.Properties["step"])
}

func TestExposes_Empty(t *testing.T) {
	rel := Exposes("", "")

	assert.Equal(t, RelExposes, rel.Type)
	// Empty strings should not be added
	_, hasJob := rel.Properties["job"]
	_, hasStep := rel.Properties["step"]
	assert.False(t, hasJob)
	assert.False(t, hasStep)
}

func TestExposes_PartialFill(t *testing.T) {
	rel := Exposes("build", "")

	assert.Equal(t, "build", rel.Properties["job"])
	_, hasStep := rel.Properties["step"]
	assert.False(t, hasStep)
}

func TestGrantsAccess(t *testing.T) {
	scopes := []string{"contents:write", "issues:read"}
	rel := GrantsAccess(scopes)

	assert.Equal(t, RelGrantsAccess, rel.Type)
	assert.Equal(t, scopes, rel.Properties["scopes"])
}

func TestVulnerableTo(t *testing.T) {
	rel := VulnerableTo("injection", "critical")

	assert.Equal(t, RelVulnerableTo, rel.Type)
	assert.Equal(t, "injection", rel.Properties["rule_id"])
	assert.Equal(t, "critical", rel.Properties["severity"])
}

func TestLeadsTo(t *testing.T) {
	rel := LeadsTo("T1588.004")

	assert.Equal(t, RelLeadsTo, rel.Type)
	assert.Equal(t, "T1588.004", rel.Properties["technique"])
}

func TestLeadsTo_Empty(t *testing.T) {
	rel := LeadsTo("")

	assert.Equal(t, RelLeadsTo, rel.Type)
	_, hasTechnique := rel.Properties["technique"]
	assert.False(t, hasTechnique)
}

func TestDiscoveredBy(t *testing.T) {
	rel := DiscoveredBy("agent-123")

	assert.Equal(t, RelDiscoveredBy, rel.Type)
	assert.Equal(t, "agent-123", rel.Properties["agent_id"])
}

func TestScannedBy(t *testing.T) {
	rel := ScannedBy("poutine", "2024-01-15T10:30:00Z")

	assert.Equal(t, RelScannedBy, rel.Type)
	assert.Equal(t, "poutine", rel.Properties["scanner_id"])
	assert.Equal(t, "2024-01-15T10:30:00Z", rel.Properties["scan_time"])
}

func TestRelationshipTypes(t *testing.T) {
	// Verify all relationship type constants are unique
	types := []RelationshipType{
		RelContains,
		RelExposes,
		RelGrantsAccess,
		RelVulnerableTo,
		RelLeadsTo,
		RelPivotFrom,
		RelExfilTo,
		RelPersistsIn,
		RelDiscoveredBy,
		RelScannedBy,
	}

	seen := make(map[RelationshipType]bool)
	for _, rt := range types {
		assert.False(t, seen[rt], "Duplicate relationship type: %s", rt)
		seen[rt] = true
	}
}
