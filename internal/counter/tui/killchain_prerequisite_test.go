// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func dispatchChain(repo string) pantry.KillChain {
	repoAsset := pantry.NewRepository("acme", repo, "github")
	vulnAsset := pantry.NewVulnerability("injection", "pkg:github/acme/"+repo, "ci.yml", 10)
	vulnAsset.SetProperty("event_triggers", []string{"workflow_dispatch"})

	return pantry.KillChain{
		VulnID: vulnAsset.ID,
		Stages: []pantry.KillChainStage{
			{Asset: repoAsset, StageType: pantry.StageEntry},
			{Asset: vulnAsset, StageType: pantry.StageExploit},
		},
	}
}

// dispatchChainFromKitchen builds a chain the way Kitchen's analyze.go actually
// stores it: Properties["trigger"] as a flat string (e.g. "workflow_dispatch"),
// NOT Properties["event_triggers"] as []string.
func dispatchChainFromKitchen(repo string) pantry.KillChain {
	repoAsset := pantry.NewRepository("acme", repo, "github")
	vulnAsset := pantry.NewVulnerability("injection", "pkg:github/acme/"+repo, "ci.yml", 10)
	vulnAsset.SetProperty("trigger", "workflow_dispatch")

	return pantry.KillChain{
		VulnID: vulnAsset.ID,
		Stages: []pantry.KillChainStage{
			{Asset: repoAsset, StageType: pantry.StageEntry},
			{Asset: vulnAsset, StageType: pantry.StageExploit},
		},
	}
}

func multiTriggerChainFromKitchen(repo string) pantry.KillChain {
	repoAsset := pantry.NewRepository("acme", repo, "github")
	vulnAsset := pantry.NewVulnerability("injection", "pkg:github/acme/"+repo, "ci.yml", 10)
	vulnAsset.SetProperty("trigger", "push, workflow_dispatch")

	return pantry.KillChain{
		VulnID: vulnAsset.ID,
		Stages: []pantry.KillChainStage{
			{Asset: repoAsset, StageType: pantry.StageEntry},
			{Asset: vulnAsset, StageType: pantry.StageExploit},
		},
	}
}

func TestDetectPrerequisites(t *testing.T) {
	tests := []struct {
		name             string
		chain            pantry.KillChain
		lootStash        []CollectedSecret
		sessionLoot      []CollectedSecret
		tokenPermissions map[string]string
		tokenInfo        *TokenInfo
		vulnerabilities  []Vulnerability
		wantNil          bool
		wantStatus       PrereqStatus
		wantSource       string
		wantHintSubstr   string
	}{
		{
			name:       "dispatch with no loot and no operator PAT",
			chain:      dispatchChain("webapp"),
			wantStatus: PrereqNotMet,
			wantSource: "",
		},
		{
			name:  "dispatch with actions:write GITHUB_TOKEN in loot",
			chain: dispatchChain("webapp"),
			lootStash: []CollectedSecret{{
				Name:   "GITHUB_TOKEN",
				Value:  "ghs_abc123",
				Scopes: []string{"actions:write", "contents:read"},
			}},
			wantStatus: PrereqMet,
			wantSource: "GITHUB_TOKEN (loot)",
		},
		{
			name:  "dispatch with classic PAT in loot",
			chain: dispatchChain("webapp"),
			lootStash: []CollectedSecret{{
				Name:  "LEAKED_PAT",
				Value: "ghp_abc123",
			}},
			wantStatus: PrereqMet,
			wantSource: "LEAKED_PAT (loot)",
		},
		{
			name:  "dispatch with active session token",
			chain: dispatchChain("webapp"),
			sessionLoot: []CollectedSecret{{
				Name:      "GITHUB_TOKEN",
				Value:     "ghs_abc123",
				Ephemeral: true,
				Type:      "github_token",
			}},
			tokenPermissions: map[string]string{"actions": "write"},
			wantStatus:       PrereqMet,
			wantSource:       "GITHUB_TOKEN (active session)",
		},
		{
			name:  "dispatch with operator PAT repo scope",
			chain: dispatchChain("webapp"),
			tokenInfo: &TokenInfo{
				Scopes: []string{"repo", "read:org"},
			},
			wantStatus: PrereqMet,
			wantSource: "operator PAT (repo scope)",
		},
		{
			name:  "dispatch with operator PAT actions:write scope",
			chain: dispatchChain("webapp"),
			tokenInfo: &TokenInfo{
				Scopes: []string{"actions:write"},
			},
			wantStatus: PrereqMet,
			wantSource: "operator PAT (actions:write)",
		},
		{
			name: "non-dispatch trigger returns nil",
			chain: func() pantry.KillChain {
				vulnAsset := pantry.NewVulnerability("injection", "pkg:github/acme/api", "ci.yml", 10)
				vulnAsset.SetProperty("event_triggers", []string{"issues"})
				return pantry.KillChain{
					VulnID: vulnAsset.ID,
					Stages: []pantry.KillChainStage{
						{Asset: vulnAsset, StageType: pantry.StageExploit},
					},
				}
			}(),
			wantNil: true,
		},
		{
			name: "no event_triggers property returns nil",
			chain: func() pantry.KillChain {
				vulnAsset := pantry.NewVulnerability("injection", "pkg:github/acme/api", "ci.yml", 10)
				return pantry.KillChain{
					VulnID: vulnAsset.ID,
					Stages: []pantry.KillChainStage{
						{Asset: vulnAsset, StageType: pantry.StageExploit},
					},
				}
			}(),
			wantNil: true,
		},
		{
			name:  "hint suggests alternate vuln in same repo",
			chain: dispatchChain("webapp"),
			vulnerabilities: []Vulnerability{
				{ID: "V001", Repository: "acme/webapp", Trigger: "issue_comment", Context: "bash_run"},
			},
			wantStatus:     PrereqNotMet,
			wantHintSubstr: "Use issue_comment vuln",
		},
		{
			name:  "hint ignores vulns in different repo",
			chain: dispatchChain("webapp"),
			vulnerabilities: []Vulnerability{
				{ID: "V001", Repository: "acme/other", Trigger: "issue_comment", Context: "bash_run"},
			},
			wantStatus:     PrereqNotMet,
			wantHintSubstr: "Pivot through another vuln",
		},
		{
			name:  "loot takes priority over operator PAT",
			chain: dispatchChain("webapp"),
			lootStash: []CollectedSecret{{
				Name:  "STOLEN_PAT",
				Value: "ghp_stolen",
			}},
			tokenInfo: &TokenInfo{
				Scopes: []string{"repo"},
			},
			wantStatus: PrereqMet,
			wantSource: "STOLEN_PAT (loot)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Model{
				lootStash:        tt.lootStash,
				sessionLoot:      tt.sessionLoot,
				tokenPermissions: tt.tokenPermissions,
				tokenInfo:        tt.tokenInfo,
				vulnerabilities:  tt.vulnerabilities,
			}

			prereq := m.detectPrerequisites(tt.chain)

			if tt.wantNil {
				assert.Nil(t, prereq)
				return
			}

			require.NotNil(t, prereq)
			assert.Equal(t, tt.wantStatus, prereq.Status)
			if tt.wantSource != "" {
				assert.Equal(t, tt.wantSource, prereq.Source)
			}
			if tt.wantHintSubstr != "" {
				assert.Contains(t, prereq.Hint, tt.wantHintSubstr)
			}
		})
	}
}

func TestFindActionsWriteToken(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []CollectedSecret
		wantNil  bool
		wantName string
	}{
		{
			name:    "empty stash",
			secrets: nil,
			wantNil: true,
		},
		{
			name: "classic PAT matches",
			secrets: []CollectedSecret{
				{Name: "MY_PAT", Value: "ghp_abc123"},
			},
			wantName: "MY_PAT",
		},
		{
			name: "fine-grained token with actions:write",
			secrets: []CollectedSecret{
				{Name: "GITHUB_TOKEN", Value: "ghs_abc", Scopes: []string{"contents:read", "actions:write"}},
			},
			wantName: "GITHUB_TOKEN",
		},
		{
			name: "token without actions:write does not match",
			secrets: []CollectedSecret{
				{Name: "GITHUB_TOKEN", Value: "ghs_abc", Scopes: []string{"contents:read"}},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findActionsWriteToken(tt.secrets)
			if tt.wantNil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.wantName, got.Name)
			}
		})
	}
}

// Kitchen stores trigger as Properties["trigger"] (string), not
// Properties["event_triggers"] ([]string). This test ensures prerequisite
// detection works with the actual Kitchen data format — a regression here
// means the kill chain modal silently drops the REQUIRES line for dispatch vulns.
func TestDetectPrerequisites_KitchenTriggerProperty(t *testing.T) {
	tests := []struct {
		name       string
		chain      pantry.KillChain
		tokenInfo  *TokenInfo
		wantNil    bool
		wantStatus PrereqStatus
	}{
		{
			name:       "Kitchen dispatch chain with operator repo scope",
			chain:      dispatchChainFromKitchen("webapp"),
			tokenInfo:  &TokenInfo{Scopes: []string{"repo"}},
			wantStatus: PrereqMet,
		},
		{
			name:       "Kitchen dispatch chain without matching scope",
			chain:      dispatchChainFromKitchen("webapp"),
			tokenInfo:  &TokenInfo{Scopes: []string{"read:org"}},
			wantStatus: PrereqNotMet,
		},
		{
			name:       "Kitchen multi-trigger chain containing workflow_dispatch",
			chain:      multiTriggerChainFromKitchen("webapp"),
			tokenInfo:  &TokenInfo{Scopes: []string{"repo"}},
			wantStatus: PrereqMet,
		},
		{
			name: "Kitchen chain with non-dispatch trigger returns nil",
			chain: func() pantry.KillChain {
				vuln := pantry.NewVulnerability("injection", "pkg:github/acme/api", "ci.yml", 10)
				vuln.SetProperty("trigger", "issue_comment")
				return pantry.KillChain{
					VulnID: vuln.ID,
					Stages: []pantry.KillChainStage{
						{Asset: vuln, StageType: pantry.StageExploit},
					},
				}
			}(),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Model{tokenInfo: tt.tokenInfo}
			prereq := m.detectPrerequisites(tt.chain)
			if tt.wantNil {
				assert.Nil(t, prereq)
				return
			}
			require.NotNil(t, prereq, "dispatch prereq must be detected from Kitchen trigger property")
			assert.Equal(t, tt.wantStatus, prereq.Status)
		})
	}
}

// JSON round-trip turns []string into []interface{} in map[string]any.
// This ensures detectPrerequisites handles both the in-memory and deserialized forms.
func TestDetectPrerequisites_JSONRoundTrip(t *testing.T) {
	chain := dispatchChain("webapp")

	data, err := json.Marshal(chain)
	require.NoError(t, err)

	var roundTripped pantry.KillChain
	require.NoError(t, json.Unmarshal(data, &roundTripped))

	m := &Model{
		tokenInfo: &TokenInfo{Scopes: []string{"repo"}},
	}

	prereq := m.detectPrerequisites(roundTripped)
	require.NotNil(t, prereq, "should detect dispatch prereq after JSON round-trip")
	assert.Equal(t, PrereqMet, prereq.Status)
	assert.Equal(t, "operator PAT (repo scope)", prereq.Source)
}

func TestExtractTargetRepo(t *testing.T) {
	repoAsset := pantry.NewRepository("acme", "webapp", "github")
	chain := pantry.KillChain{
		Stages: []pantry.KillChainStage{
			{Asset: repoAsset, StageType: pantry.StageEntry},
		},
	}
	assert.Equal(t, "acme/webapp", extractTargetRepo(chain))

	emptyChain := pantry.KillChain{}
	assert.Equal(t, "", extractTargetRepo(emptyChain))
}
