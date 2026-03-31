// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

// GraphMessage is the envelope for all graph WebSocket messages.
type GraphMessage struct {
	Type string `json:"type"` // "snapshot", "delta", "ping", "pong"
	Data any    `json:"data,omitempty"`
}

// GraphSnapshot is the initial full graph state sent on connect.
type GraphSnapshot struct {
	Version int64       `json:"version"`
	Nodes   []GraphNode `json:"nodes"`
	Edges   []GraphEdge `json:"edges"`
}

// GraphDelta contains incremental changes to the graph.
type GraphDelta struct {
	Version      int64        `json:"version"`
	AddedNodes   []GraphNode  `json:"added_nodes,omitempty"`
	UpdatedNodes []NodeUpdate `json:"updated_nodes,omitempty"`
	AddedEdges   []GraphEdge  `json:"added_edges,omitempty"`
	RemovedNodes []string     `json:"removed_nodes,omitempty"`
	RemovedEdges []EdgeRef    `json:"removed_edges,omitempty"`
}

// EdgeRef identifies an edge by its source and target.
type EdgeRef struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// GraphNode represents a node in the graph visualization.
type GraphNode struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Label      string         `json:"label"`
	State      string         `json:"state"`
	Properties map[string]any `json:"properties,omitempty"`
}

// NodeUpdate represents a change to an existing node (state, properties, or label).
type NodeUpdate struct {
	ID         string         `json:"id"`
	OldState   string         `json:"old_state"`
	NewState   string         `json:"new_state"`
	Label      string         `json:"label,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// GraphEdge represents an edge in the graph visualization.
type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	Label  string `json:"label,omitempty"`
}

// AssetToGraphNode converts a pantry Asset to a GraphNode.
func AssetToGraphNode(asset pantry.Asset) GraphNode {
	label := asset.Name
	if asset.Type == pantry.AssetJob {
		if displayName, ok := asset.Properties["display_name"].(string); ok && displayName != "" {
			label = asset.Name + " (" + displayName + ")"
		}
	}
	if asset.Type == pantry.AssetRepository {
		if private, ok := asset.Properties["private"].(bool); ok && private {
			label = "🔒 " + label
		}
		if sshAccess, ok := asset.Properties["ssh_access"].(string); ok {
			switch sshAccess {
			case "write":
				label += " [ssh:w]"
			case "read":
				label += " [ssh:r]"
			}
		}
	}
	return GraphNode{
		ID:         asset.ID,
		Type:       string(asset.Type),
		Label:      label,
		State:      string(asset.State),
		Properties: asset.Properties,
	}
}

// EdgeToGraphEdge converts a pantry Edge to a GraphEdge.
func EdgeToGraphEdge(edge pantry.Edge) GraphEdge {
	return GraphEdge{
		Source: edge.From,
		Target: edge.To,
		Type:   string(edge.Relationship.Type),
	}
}
