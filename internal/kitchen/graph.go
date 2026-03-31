// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"net/http"
)

type graphData struct {
	Nodes []GraphNode `json:"nodes"`
	Links []GraphEdge `json:"links"`
}

func (h *Handler) handleGraph(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(graphCytoscapeHTML))
}

func (h *Handler) handleGraphData(w http.ResponseWriter, _ *http.Request) {
	p := h.Pantry()
	assets := p.AllAssets()
	edges := p.AllRelationships()

	data := graphData{
		Nodes: make([]GraphNode, 0, len(assets)),
		Links: make([]GraphEdge, 0, len(edges)),
	}

	for _, asset := range assets {
		data.Nodes = append(data.Nodes, AssetToGraphNode(asset))
	}

	for _, edge := range edges {
		data.Links = append(data.Links, EdgeToGraphEdge(edge))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}
