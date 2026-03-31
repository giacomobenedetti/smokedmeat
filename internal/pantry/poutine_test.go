// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOffensiveRules(t *testing.T) {
	// Verify the list is not empty
	assert.NotEmpty(t, OffensiveRules)

	// Verify critical rules are present
	assert.Contains(t, OffensiveRules, "untrusted_checkout_exec")
	assert.Contains(t, OffensiveRules, "injection")
	assert.Contains(t, OffensiveRules, "pr_runs_on_self_hosted")

	// Verify high rules are present
	assert.Contains(t, OffensiveRules, "debug_enabled")
	assert.Contains(t, OffensiveRules, "excessive_permissions")
}

func TestIsOffensiveRule(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected bool
	}{
		{"injection", true},
		{"untrusted_checkout_exec", true},
		{"debug_enabled", true},
		{"excessive_permissions", true},
		{"some_warning_rule", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsOffensiveRule(tt.ruleID))
		})
	}
}

func TestParsePurl(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		provider string
		org      string
		repo     string
	}{
		{
			name:     "github purl",
			purl:     "pkg:github/acme/api",
			provider: "github",
			org:      "acme",
			repo:     "api",
		},
		{
			name:     "gitlab purl",
			purl:     "pkg:gitlab/mygroup/myproject",
			provider: "gitlab",
			org:      "mygroup",
			repo:     "myproject",
		},
		{
			name:     "purl with version",
			purl:     "pkg:github/acme/api@main",
			provider: "github",
			org:      "acme",
			repo:     "api",
		},
		{
			name:     "purl with full ref",
			purl:     "pkg:github/owner/repo@refs/heads/feature",
			provider: "github",
			org:      "owner",
			repo:     "repo",
		},
		{
			name:     "invalid purl - too few parts",
			purl:     "pkg:github/acme",
			provider: "",
			org:      "",
			repo:     "",
		},
		{
			name:     "invalid purl - empty",
			purl:     "",
			provider: "",
			org:      "",
			repo:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, org, repo := ParsePurl(tt.purl)
			assert.Equal(t, tt.provider, provider)
			assert.Equal(t, tt.org, org)
			assert.Equal(t, tt.repo, repo)
		})
	}
}

func TestPantry_ImportPoutineFindings(t *testing.T) {
	p := New()

	insights := &PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: []FindingResult{
			{
				RuleID: "injection",
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path:    ".github/workflows/ci.yml",
					Line:    42,
					Job:     "build",
					Step:    "run-tests",
					Details: "Command injection via untrusted input",
				},
			},
			{
				RuleID: "debug_enabled",
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path: ".github/workflows/ci.yml",
					Line: 15,
				},
			},
		},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	// Should have: 1 org + 1 repo + 1 workflow + 2 vulnerabilities
	assert.Equal(t, 5, p.Size())

	// Verify org was created
	orgs := p.GetAssetsByType(AssetOrganization)
	require.Len(t, orgs, 1)
	assert.Equal(t, "acme", orgs[0].Name)
	assert.Equal(t, "github", orgs[0].Provider)

	// Verify repo was created
	repos := p.GetAssetsByType(AssetRepository)
	require.Len(t, repos, 1)
	assert.Equal(t, "api", repos[0].Name)
	assert.Equal(t, "github", repos[0].Provider)

	// Verify workflow was created
	workflows := p.GetAssetsByType(AssetWorkflow)
	require.Len(t, workflows, 1)
	assert.Equal(t, "ci.yml", workflows[0].Name)

	// Verify vulnerabilities were created
	vulns := p.FindVulnerabilities()
	require.Len(t, vulns, 2)

	// Check that injection vuln has correct properties
	var injectionVuln *Asset
	for i, v := range vulns {
		if v.RuleID == "injection" {
			injectionVuln = &vulns[i]
			break
		}
	}
	require.NotNil(t, injectionVuln)
	assert.Equal(t, "critical", injectionVuln.Severity)
	assert.Equal(t, "build", injectionVuln.Properties["job"])
	assert.Equal(t, "run-tests", injectionVuln.Properties["step"])

	// Verify relationships were created
	edges := p.AllRelationships()
	assert.GreaterOrEqual(t, len(edges), 4) // org->repo, repo->workflow, workflow->vuln1, workflow->vuln2
}

func TestPantry_ImportPoutineFindings_FilterNonOffensive(t *testing.T) {
	p := New()

	insights := &PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: []FindingResult{
			{
				RuleID: "injection", // Offensive
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path: ".github/workflows/ci.yml",
					Line: 42,
				},
			},
			{
				RuleID: "some_warning_rule", // Not offensive - should be filtered
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path: ".github/workflows/ci.yml",
					Line: 10,
				},
			},
		},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	// Only the injection vuln should be imported
	vulns := p.FindVulnerabilities()
	assert.Len(t, vulns, 1)
	assert.Equal(t, "injection", vulns[0].RuleID)
}

func TestPantry_ImportPoutineFindings_NilInsights(t *testing.T) {
	p := New()

	err := p.ImportPoutineFindings(nil)
	require.NoError(t, err)
	assert.Equal(t, 0, p.Size())
}

func TestPantry_ImportPoutineFindings_EmptyFindings(t *testing.T) {
	p := New()

	insights := &PackageInsights{
		Purl:            "pkg:github/acme/api",
		FindingsResults: []FindingResult{},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	// Only org + repo should be created
	assert.Equal(t, 2, p.Size())
}

func TestPantry_ImportPoutineFindings_MultipleWorkflows(t *testing.T) {
	p := New()

	insights := &PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: []FindingResult{
			{
				RuleID: "injection",
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path: ".github/workflows/ci.yml",
					Line: 10,
				},
			},
			{
				RuleID: "debug_enabled",
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path: ".github/workflows/cd.yml",
					Line: 20,
				},
			},
		},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	// Should have 2 workflows
	workflows := p.GetAssetsByType(AssetWorkflow)
	assert.Len(t, workflows, 2)
}

func TestPantry_ImportPoutineFindings_NoPath(t *testing.T) {
	p := New()

	insights := &PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: []FindingResult{
			{
				RuleID: "injection",
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Line: 10, // No path
				},
			},
		},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	// Vuln should be connected directly to repo
	edges := p.AllRelationships()
	var foundRepoToVuln bool
	for _, e := range edges {
		if e.Relationship.Type == RelVulnerableTo {
			foundRepoToVuln = true
		}
	}
	assert.True(t, foundRepoToVuln)
}

func TestPantry_ImportPoutineFindings_WithEventTriggers(t *testing.T) {
	p := New()

	insights := &PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: []FindingResult{
			{
				RuleID: "injection",
				Purl:   "pkg:github/acme/api",
				Meta: FindingMeta{
					Path:          ".github/workflows/ci.yml",
					Line:          10,
					EventTriggers: []string{"pull_request", "push"},
				},
			},
		},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	vulns := p.FindVulnerabilities()
	require.Len(t, vulns, 1)
	assert.Equal(t, []string{"pull_request", "push"}, vulns[0].Properties["event_triggers"])
}

func TestPantry_ImportFindingsBatch(t *testing.T) {
	p := New()

	batch := []*PackageInsights{
		{
			Purl: "pkg:github/acme/api",
			FindingsResults: []FindingResult{
				{
					RuleID: "injection",
					Purl:   "pkg:github/acme/api",
					Meta:   FindingMeta{Path: "ci.yml", Line: 10},
				},
			},
		},
		{
			Purl: "pkg:github/acme/web",
			FindingsResults: []FindingResult{
				{
					RuleID: "debug_enabled",
					Purl:   "pkg:github/acme/web",
					Meta:   FindingMeta{Path: "build.yml", Line: 20},
				},
			},
		},
	}

	err := p.ImportFindingsBatch(batch)
	require.NoError(t, err)

	// Should have 2 repos
	repos := p.GetAssetsByType(AssetRepository)
	assert.Len(t, repos, 2)

	// Should have 2 vulns
	vulns := p.FindVulnerabilities()
	assert.Len(t, vulns, 2)
}

func TestPantry_ImportFindingsBatch_WithNil(t *testing.T) {
	p := New()

	batch := []*PackageInsights{
		{
			Purl: "pkg:github/acme/api",
			FindingsResults: []FindingResult{
				{
					RuleID: "injection",
					Purl:   "pkg:github/acme/api",
					Meta:   FindingMeta{Path: "ci.yml", Line: 10},
				},
			},
		},
		nil, // Should be skipped
	}

	err := p.ImportFindingsBatch(batch)
	require.NoError(t, err)

	// Should still have imported the first one
	repos := p.GetAssetsByType(AssetRepository)
	assert.Len(t, repos, 1)
}

func TestPantry_ImportPoutineFindings_DefaultProvider(t *testing.T) {
	p := New()

	// Invalid purl that doesn't parse properly
	insights := &PackageInsights{
		Purl: "invalid",
		FindingsResults: []FindingResult{
			{
				RuleID: "injection",
				Purl:   "invalid",
				Meta:   FindingMeta{Path: "ci.yml", Line: 10},
			},
		},
	}

	err := p.ImportPoutineFindings(insights)
	require.NoError(t, err)

	// Should default to github provider
	repos := p.GetAssetsByType(AssetRepository)
	require.Len(t, repos, 1)
	assert.Equal(t, "github", repos[0].Provider)
}
