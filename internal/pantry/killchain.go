// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import "strings"

type StageType string

const (
	StageEntry       StageType = "entry"
	StageExploit     StageType = "exploit"
	StageCredential  StageType = "credential"
	StagePivotTarget StageType = "pivot_target"
)

type KillChainStage struct {
	Asset     Asset
	StageType StageType
	Confirmed bool
	EdgeLabel string
}

type PivotProjection struct {
	CredentialName string
	CredentialType string
	Provider       string
	Actions        []string
	Commands       []string
}

type KillChain struct {
	VulnID      string
	Stages      []KillChainStage
	Projections []PivotProjection
}

func (p *Pantry) TraceKillChain(vulnID string) (KillChain, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	vulnAsset, ok := p.assets[vulnID]
	if !ok {
		return KillChain{}, ErrAssetNotFound
	}

	chain := KillChain{VulnID: vulnID}

	ancestry := p.walkAncestry(vulnID)

	for _, ancestor := range ancestry {
		st := classifyStage(ancestor.Type)
		chain.Stages = append(chain.Stages, KillChainStage{
			Asset:     ancestor,
			StageType: st,
			Confirmed: ancestor.State == StateExploited,
			EdgeLabel: string(RelContains),
		})
	}

	chain.Stages = append(chain.Stages, KillChainStage{
		Asset:     vulnAsset,
		StageType: StageExploit,
		Confirmed: vulnAsset.State == StateExploited,
		EdgeLabel: string(RelVulnerableTo),
	})

	credentialParents := p.findCredentialParents(vulnID, ancestry)
	for _, parentID := range credentialParents {
		prefix := parentID + "|"
		for key, rel := range p.edges {
			if len(key) > len(prefix) && key[:len(prefix)] == prefix && rel.Type == RelExposes {
				_, toID := parseEdgeKey(key)
				if credAsset, exists := p.assets[toID]; exists {
					if credAsset.Type == AssetSecret || credAsset.Type == AssetToken || credAsset.Type == AssetCloud {
						chain.Stages = append(chain.Stages, KillChainStage{
							Asset:     credAsset,
							StageType: StageCredential,
							Confirmed: credAsset.State == StateExploited,
							EdgeLabel: string(RelExposes),
						})
						projections := ProjectPivots(credAsset)
						chain.Projections = append(chain.Projections, projections...)
					}
				}
			}
		}
	}

	return chain, nil
}

func (p *Pantry) walkAncestry(id string) []Asset {
	var ancestry []Asset
	visited := map[string]bool{id: true}
	current := id

	for {
		sourceIDs := p.reverseEdges[current]
		if len(sourceIDs) == 0 {
			break
		}

		var parent string
		for _, srcID := range sourceIDs {
			if visited[srcID] {
				continue
			}
			key := edgeKey(srcID, current)
			if rel, ok := p.edges[key]; ok && rel.Type == RelContains {
				parent = srcID
				break
			}
		}
		if parent == "" {
			for _, srcID := range sourceIDs {
				if !visited[srcID] {
					parent = srcID
					break
				}
			}
		}
		if parent == "" {
			break
		}

		visited[parent] = true
		if asset, ok := p.assets[parent]; ok {
			ancestry = append([]Asset{asset}, ancestry...)
		}
		current = parent
	}

	return ancestry
}

func (p *Pantry) findCredentialParents(vulnID string, ancestry []Asset) []string {
	var parents []string

	directParents := p.reverseEdges[vulnID]
	for _, pid := range directParents {
		if a, ok := p.assets[pid]; ok {
			if a.Type == AssetJob || a.Type == AssetWorkflow {
				parents = append(parents, pid)
			}
		}
	}

	if len(parents) == 0 {
		for i := len(ancestry) - 1; i >= 0; i-- {
			a := ancestry[i]
			if a.Type == AssetJob || a.Type == AssetWorkflow {
				parents = append(parents, a.ID)
				break
			}
		}
	}

	return parents
}

func classifyStage(t AssetType) StageType {
	switch t {
	case AssetVulnerability:
		return StageExploit
	case AssetSecret, AssetToken, AssetCloud:
		return StageCredential
	default:
		return StageEntry
	}
}

func (kc KillChain) CredentialCount() int {
	count := 0
	for _, s := range kc.Stages {
		if s.StageType == StageCredential {
			count++
		}
	}
	return count
}

func (kc KillChain) CloudPivotCount() int {
	count := 0
	for _, p := range kc.Projections {
		if isCloudProvider(p.Provider) {
			count++
		}
	}
	return count
}

func isCloudProvider(provider string) bool {
	switch strings.ToLower(provider) {
	case "aws", "gcp", "azure":
		return true
	default:
		return false
	}
}
