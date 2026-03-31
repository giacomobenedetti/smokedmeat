// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/hmdsefi/gograph"
)

var (
	// ErrAssetNotFound is returned when an asset doesn't exist in the graph.
	ErrAssetNotFound = errors.New("asset not found")

	// ErrAssetExists is returned when trying to add a duplicate asset.
	ErrAssetExists = errors.New("asset already exists")
)

// Pantry stores the attack surface graph.
// Thread-safe for concurrent access.
type Pantry struct {
	mu    sync.RWMutex
	graph gograph.Graph[string]

	// Asset data storage (graph stores topology only)
	assets map[string]Asset

	// Edge data storage (keyed by "from|to")
	edges map[string]Relationship

	// Reverse edge index (destination ID → list of source IDs)
	reverseEdges map[string][]string

	// Index for faster lookups by type
	byType map[AssetType]map[string]struct{}

	// Observer support for real-time notifications
	obsMu     sync.RWMutex
	observers []Observer

	// Version counter for change tracking
	version int64
}

// New creates a new Pantry with an empty directed graph.
func New() *Pantry {
	return &Pantry{
		graph:        gograph.New[string](gograph.Directed()),
		assets:       make(map[string]Asset),
		edges:        make(map[string]Relationship),
		reverseEdges: make(map[string][]string),
		byType:       make(map[AssetType]map[string]struct{}),
	}
}

// edgeKey generates a unique key for an edge.
func edgeKey(from, to string) string {
	return from + "|" + to
}

// AddAsset adds or updates an asset vertex.
func (p *Pantry) AddAsset(asset Asset) error {
	p.mu.Lock()

	existing := p.graph.GetVertexByID(asset.ID)
	if existing != nil {
		oldAsset := p.assets[asset.ID]
		oldState := oldAsset.State
		hasNewKeys := false
		for k := range asset.Properties {
			if _, has := oldAsset.Properties[k]; !has {
				hasNewKeys = true
				break
			}
		}
		if len(oldAsset.Properties) > 0 {
			if asset.Properties == nil {
				asset.Properties = make(map[string]any)
			}
			for k, v := range oldAsset.Properties {
				if _, has := asset.Properties[k]; !has {
					asset.Properties[k] = v
				}
			}
		}
		p.assets[asset.ID] = asset
		p.version++
		p.mu.Unlock()

		if oldState != asset.State || hasNewKeys {
			p.notifyAssetUpdated(asset, oldState)
		}
		return nil
	}

	p.graph.AddVertexByLabel(asset.ID)
	p.assets[asset.ID] = asset

	if p.byType[asset.Type] == nil {
		p.byType[asset.Type] = make(map[string]struct{})
	}
	p.byType[asset.Type][asset.ID] = struct{}{}
	p.version++
	p.mu.Unlock()

	p.notifyAssetAdded(asset)
	return nil
}

// AddRelationship adds an edge between assets.
func (p *Pantry) AddRelationship(fromID, toID string, rel Relationship) error {
	p.mu.Lock()

	fromVertex := p.graph.GetVertexByID(fromID)
	if fromVertex == nil {
		p.mu.Unlock()
		return ErrAssetNotFound
	}
	toVertex := p.graph.GetVertexByID(toID)
	if toVertex == nil {
		p.mu.Unlock()
		return ErrAssetNotFound
	}

	_, err := p.graph.AddEdge(fromVertex, toVertex)
	if err != nil {
		p.mu.Unlock()
		return err
	}

	p.edges[edgeKey(fromID, toID)] = rel
	p.reverseEdges[toID] = append(p.reverseEdges[toID], fromID)
	p.version++
	p.mu.Unlock()

	p.notifyRelationshipAdded(fromID, toID, rel)
	return nil
}

// RemoveAsset removes an asset and all its relationships.
func (p *Pantry) RemoveAsset(id string) error {
	p.mu.Lock()

	asset, ok := p.assets[id]
	if !ok {
		p.mu.Unlock()
		return ErrAssetNotFound
	}

	if p.byType[asset.Type] != nil {
		delete(p.byType[asset.Type], id)
	}

	var edgesToRemove []string
	for key := range p.edges {
		from, to := parseEdgeKey(key)
		if from == id || to == id {
			edgesToRemove = append(edgesToRemove, key)
		}
	}
	for _, key := range edgesToRemove {
		_, to := parseEdgeKey(key)
		if to != id {
			p.removeReverseEdge(to, id)
		}
		delete(p.edges, key)
	}
	delete(p.reverseEdges, id)

	vertex := p.graph.GetVertexByID(id)
	if vertex != nil {
		p.graph.RemoveVertices(vertex)
	}

	delete(p.assets, id)
	p.version++
	p.mu.Unlock()

	p.notifyAssetRemoved(id)
	return nil
}

// RemoveRelationship removes an edge between assets.
func (p *Pantry) RemoveRelationship(fromID, toID string) error {
	p.mu.Lock()

	key := edgeKey(fromID, toID)
	if _, ok := p.edges[key]; !ok {
		p.mu.Unlock()
		return errors.New("relationship not found")
	}

	delete(p.edges, key)
	p.removeReverseEdge(toID, fromID)

	fromVertex := p.graph.GetVertexByID(fromID)
	toVertex := p.graph.GetVertexByID(toID)
	if fromVertex != nil && toVertex != nil {
		edge := gograph.NewEdge(fromVertex, toVertex)
		p.graph.RemoveEdges(edge)
	}

	p.version++
	p.mu.Unlock()

	p.notifyRelationshipRemoved(fromID, toID)
	return nil
}

// GetAsset retrieves an asset by ID.
func (p *Pantry) GetAsset(id string) (Asset, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	asset, ok := p.assets[id]
	if !ok {
		return Asset{}, ErrAssetNotFound
	}
	return asset, nil
}

// HasAsset checks if an asset exists.
func (p *Pantry) HasAsset(id string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	_, ok := p.assets[id]
	return ok
}

// GetAssetsByType returns all assets of a given type.
func (p *Pantry) GetAssetsByType(assetType AssetType) []Asset {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ids := p.byType[assetType]
	if ids == nil {
		return nil
	}

	assets := make([]Asset, 0, len(ids))
	for id := range ids {
		if asset, ok := p.assets[id]; ok {
			assets = append(assets, asset)
		}
	}
	return assets
}

// GetNeighbors returns assets within N hops of the given asset.
func (p *Pantry) GetNeighbors(id string, hops int) ([]Asset, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.assets[id]; !ok {
		return nil, ErrAssetNotFound
	}

	if hops <= 0 {
		asset := p.assets[id]
		return []Asset{asset}, nil
	}

	visited := make(map[string]int)
	visited[id] = 0
	queue := []string{id}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentDist := visited[current]
		if currentDist >= hops {
			continue
		}

		currentVertex := p.graph.GetVertexByID(current)
		if currentVertex == nil {
			continue
		}

		for _, neighbor := range currentVertex.Neighbors() {
			neighborID := neighbor.Label()
			if _, seen := visited[neighborID]; !seen {
				visited[neighborID] = currentDist + 1
				queue = append(queue, neighborID)
			}
		}
	}

	assets := make([]Asset, 0, len(visited))
	for assetID := range visited {
		if asset, ok := p.assets[assetID]; ok {
			assets = append(assets, asset)
		}
	}

	return assets, nil
}

// AllAssets returns all assets in the graph.
func (p *Pantry) AllAssets() []Asset {
	p.mu.RLock()
	defer p.mu.RUnlock()

	assets := make([]Asset, 0, len(p.assets))
	for _, asset := range p.assets {
		assets = append(assets, asset)
	}
	return assets
}

// AllRelationships returns all edges in the graph.
func (p *Pantry) AllRelationships() []Edge {
	p.mu.RLock()
	defer p.mu.RUnlock()

	graphEdges := p.graph.AllEdges()
	result := make([]Edge, 0, len(graphEdges))

	for _, e := range graphEdges {
		fromID := e.Source().Label()
		toID := e.Destination().Label()
		rel := p.edges[edgeKey(fromID, toID)]
		result = append(result, Edge{
			From:         fromID,
			To:           toID,
			Relationship: rel,
		})
	}

	return result
}

// Size returns the number of assets in the graph.
func (p *Pantry) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.assets)
}

// EdgeCount returns the number of relationships in the graph.
func (p *Pantry) EdgeCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.graph.AllEdges())
}

// Version returns the current version of the graph.
// Version is incremented on each mutation.
func (p *Pantry) Version() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.version
}

// UpdateAssetState updates the state of an asset.
func (p *Pantry) UpdateAssetState(id string, state AssetState) error {
	p.mu.Lock()

	asset, ok := p.assets[id]
	if !ok {
		p.mu.Unlock()
		return ErrAssetNotFound
	}

	oldState := asset.State
	if oldState == state {
		p.mu.Unlock()
		return nil
	}

	asset.State = state
	p.assets[id] = asset
	p.version++
	p.mu.Unlock()

	p.notifyAssetUpdated(asset, oldState)
	return nil
}

// FindVulnerabilities returns all vulnerability assets.
func (p *Pantry) FindVulnerabilities() []Asset {
	return p.GetAssetsByType(AssetVulnerability)
}

// FindSecrets returns all secret assets.
func (p *Pantry) FindSecrets() []Asset {
	return p.GetAssetsByType(AssetSecret)
}

// FindHighValueTargets returns assets marked as high value.
func (p *Pantry) FindHighValueTargets() []Asset {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var targets []Asset
	for _, asset := range p.assets {
		if asset.State == StateHighValue {
			targets = append(targets, asset)
		}
	}
	return targets
}

// GetAttackPaths finds paths from a source asset to target assets of given types.
// Uses BFS to find shortest paths to each target.
func (p *Pantry) GetAttackPaths(sourceID string, targetTypes []AssetType) [][]Asset {
	p.mu.RLock()
	defer p.mu.RUnlock()

	sourceVertex := p.graph.GetVertexByID(sourceID)
	if sourceVertex == nil {
		return nil
	}

	targetSet := make(map[string]struct{})
	for _, t := range targetTypes {
		if ids, ok := p.byType[t]; ok {
			for id := range ids {
				targetSet[id] = struct{}{}
			}
		}
	}

	if len(targetSet) == 0 {
		return nil
	}

	var paths [][]Asset
	for targetID := range targetSet {
		path := p.findPath(sourceID, targetID)
		if len(path) > 0 {
			paths = append(paths, path)
		}
	}

	return paths
}

// findPath finds a path between two vertices using BFS.
func (p *Pantry) findPath(fromID, toID string) []Asset {
	if fromID == toID {
		if asset, ok := p.assets[fromID]; ok {
			return []Asset{asset}
		}
		return nil
	}

	startVertex := p.graph.GetVertexByID(fromID)
	if startVertex == nil {
		return nil
	}

	parent := make(map[string]string)
	visited := make(map[string]bool)
	queue := []string{fromID}
	visited[fromID] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == toID {
			var path []Asset
			for node := toID; node != ""; node = parent[node] {
				if asset, ok := p.assets[node]; ok {
					path = append([]Asset{asset}, path...)
				}
				if node == fromID {
					break
				}
			}
			return path
		}

		currentVertex := p.graph.GetVertexByID(current)
		if currentVertex == nil {
			continue
		}

		for _, neighbor := range currentVertex.Neighbors() {
			neighborID := neighbor.Label()
			if !visited[neighborID] {
				visited[neighborID] = true
				parent[neighborID] = current
				queue = append(queue, neighborID)
			}
		}
	}

	return nil
}

// Clear removes all assets and relationships from the graph.
func (p *Pantry) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.graph = gograph.New[string](gograph.Directed())
	p.assets = make(map[string]Asset)
	p.edges = make(map[string]Relationship)
	p.reverseEdges = make(map[string][]string)
	p.byType = make(map[AssetType]map[string]struct{})
}

// pantryData is the serializable form of Pantry.
type pantryData struct {
	Assets []Asset `json:"assets"`
	Edges  []Edge  `json:"edges"`
}

// MarshalJSON serializes the Pantry to JSON.
func (p *Pantry) MarshalJSON() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data := pantryData{
		Assets: make([]Asset, 0, len(p.assets)),
		Edges:  make([]Edge, 0, len(p.edges)),
	}

	for _, asset := range p.assets {
		data.Assets = append(data.Assets, asset)
	}

	for key, rel := range p.edges {
		from, to := parseEdgeKey(key)
		data.Edges = append(data.Edges, Edge{
			From:         from,
			To:           to,
			Relationship: rel,
		})
	}

	return json.Marshal(data)
}

// UnmarshalJSON deserializes JSON into a Pantry.
func (p *Pantry) UnmarshalJSON(data []byte) error {
	var pd pantryData
	if err := json.Unmarshal(data, &pd); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.graph = gograph.New[string](gograph.Directed())
	p.assets = make(map[string]Asset)
	p.edges = make(map[string]Relationship)
	p.reverseEdges = make(map[string][]string)
	p.byType = make(map[AssetType]map[string]struct{})

	for _, asset := range pd.Assets {
		p.graph.AddVertexByLabel(asset.ID)
		p.assets[asset.ID] = asset
		if p.byType[asset.Type] == nil {
			p.byType[asset.Type] = make(map[string]struct{})
		}
		p.byType[asset.Type][asset.ID] = struct{}{}
	}

	for _, edge := range pd.Edges {
		fromVertex := p.graph.GetVertexByID(edge.From)
		toVertex := p.graph.GetVertexByID(edge.To)
		if fromVertex != nil && toVertex != nil {
			_, _ = p.graph.AddEdge(fromVertex, toVertex)
			p.edges[edgeKey(edge.From, edge.To)] = edge.Relationship
			p.reverseEdges[edge.To] = append(p.reverseEdges[edge.To], edge.From)
		}
	}

	return nil
}

// GetPredecessors returns assets with edges TO this node (reverse lookup).
func (p *Pantry) GetPredecessors(id string) []Asset {
	p.mu.RLock()
	defer p.mu.RUnlock()

	sourceIDs := p.reverseEdges[id]
	assets := make([]Asset, 0, len(sourceIDs))
	for _, srcID := range sourceIDs {
		if asset, ok := p.assets[srcID]; ok {
			assets = append(assets, asset)
		}
	}
	return assets
}

// GetOutgoingEdges returns edges FROM this node with relationship data.
func (p *Pantry) GetOutgoingEdges(id string) []Edge {
	p.mu.RLock()
	defer p.mu.RUnlock()

	prefix := id + "|"
	var result []Edge
	for key, rel := range p.edges {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			_, to := parseEdgeKey(key)
			result = append(result, Edge{
				From:         id,
				To:           to,
				Relationship: rel,
			})
		}
	}
	return result
}

func (p *Pantry) removeReverseEdge(toID, fromID string) {
	sources := p.reverseEdges[toID]
	for i, src := range sources {
		if src == fromID {
			p.reverseEdges[toID] = append(sources[:i], sources[i+1:]...)
			break
		}
	}
	if len(p.reverseEdges[toID]) == 0 {
		delete(p.reverseEdges, toID)
	}
}

// parseEdgeKey splits "from|to" back into from and to.
func parseEdgeKey(key string) (from, to string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
