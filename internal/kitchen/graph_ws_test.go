// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestAssetToGraphNode_BasicFields(t *testing.T) {
	asset := pantry.Asset{
		ID:    "repo:acme/api",
		Type:  pantry.AssetRepository,
		Name:  "acme/api",
		State: pantry.StateNew,
	}

	node := AssetToGraphNode(asset)

	assert.Equal(t, "repo:acme/api", node.ID)
	assert.Equal(t, "repository", node.Type)
	assert.Equal(t, "acme/api", node.Label)
	assert.Equal(t, "new", node.State)
}

func TestAssetToGraphNode_JobWithDisplayName(t *testing.T) {
	asset := pantry.Asset{
		ID:    "job:build-123",
		Type:  pantry.AssetJob,
		Name:  "build-123",
		State: pantry.StateExploited,
		Properties: map[string]any{
			"display_name": "Build & Test",
		},
	}

	node := AssetToGraphNode(asset)

	assert.Equal(t, "build-123 (Build & Test)", node.Label)
}

func TestAssetToGraphNode_JobWithoutDisplayName(t *testing.T) {
	asset := pantry.Asset{
		ID:         "job:deploy",
		Type:       pantry.AssetJob,
		Name:       "deploy",
		State:      pantry.StateNew,
		Properties: map[string]any{},
	}

	node := AssetToGraphNode(asset)

	assert.Equal(t, "deploy", node.Label)
}

func TestAssetToGraphNode_JobWithEmptyDisplayName(t *testing.T) {
	asset := pantry.Asset{
		ID:    "job:test",
		Type:  pantry.AssetJob,
		Name:  "test",
		State: pantry.StateNew,
		Properties: map[string]any{
			"display_name": "",
		},
	}

	node := AssetToGraphNode(asset)

	assert.Equal(t, "test", node.Label)
}

func TestAssetToGraphNode_PreservesProperties(t *testing.T) {
	props := map[string]any{
		"severity": "high",
		"rule_id":  "INJECTION_001",
	}
	asset := pantry.Asset{
		ID:         "vuln:v1",
		Type:       pantry.AssetVulnerability,
		Name:       "injection",
		State:      pantry.StateValidated,
		Properties: props,
	}

	node := AssetToGraphNode(asset)

	assert.Equal(t, "high", node.Properties["severity"])
	assert.Equal(t, "INJECTION_001", node.Properties["rule_id"])
}

func TestAssetToGraphNode_RepositorySSHAccessLabel(t *testing.T) {
	asset := pantry.Asset{
		ID:    "repo:acme/api",
		Type:  pantry.AssetRepository,
		Name:  "acme/api",
		State: pantry.StateValidated,
		Properties: map[string]any{
			"private":    true,
			"ssh_access": "write",
		},
	}

	node := AssetToGraphNode(asset)

	assert.Equal(t, "🔒 acme/api [ssh:w]", node.Label)
}

func TestEdgeToGraphEdge(t *testing.T) {
	edge := pantry.Edge{
		From: "repo:acme/api",
		To:   "wf:ci.yml",
		Relationship: pantry.Relationship{
			Type: pantry.RelContains,
		},
	}

	graphEdge := EdgeToGraphEdge(edge)

	assert.Equal(t, "repo:acme/api", graphEdge.Source)
	assert.Equal(t, "wf:ci.yml", graphEdge.Target)
	assert.Equal(t, "contains", graphEdge.Type)
}

func TestEdgeToGraphEdge_AllRelTypes(t *testing.T) {
	types := []pantry.RelationshipType{
		pantry.RelContains,
		pantry.RelExposes,
		pantry.RelGrantsAccess,
		pantry.RelVulnerableTo,
		pantry.RelLeadsTo,
		pantry.RelPivotFrom,
	}

	for _, relType := range types {
		t.Run(string(relType), func(t *testing.T) {
			edge := pantry.Edge{
				From:         "a",
				To:           "b",
				Relationship: pantry.Relationship{Type: relType},
			}
			graphEdge := EdgeToGraphEdge(edge)
			assert.Equal(t, string(relType), graphEdge.Type)
		})
	}
}
