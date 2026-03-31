// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildRealisticGraph(t *testing.T) *Pantry {
	t.Helper()
	p := New()

	org := NewOrganization("acme-corp", "github")
	require.NoError(t, p.AddAsset(org))

	repo := NewRepository("acme-corp", "webapp", "github")
	repo.State = StateValidated
	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddRelationship(org.ID, repo.ID, Contains()))

	wf := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	wf.State = StateValidated
	require.NoError(t, p.AddAsset(wf))
	require.NoError(t, p.AddRelationship(repo.ID, wf.ID, Contains()))

	job := NewJob(wf.ID, "build")
	job.State = StateValidated
	require.NoError(t, p.AddAsset(job))
	require.NoError(t, p.AddRelationship(wf.ID, job.ID, Contains()))

	vuln := NewVulnerability("injection", "pkg:github/acme-corp/webapp", ".github/workflows/ci.yml", 45)
	vuln.State = StateHighValue
	vuln.SetProperty("title", "Injection (issue body)")
	vuln.SetProperty("trigger", "issues")
	require.NoError(t, p.AddAsset(vuln))
	require.NoError(t, p.AddRelationship(job.ID, vuln.ID, VulnerableTo("injection", "critical")))

	secret := NewSecret("AWS_ACCESS_KEY_ID", job.ID, "github")
	secret.State = StateHighValue
	require.NoError(t, p.AddAsset(secret))
	require.NoError(t, p.AddRelationship(job.ID, secret.ID, Exposes("build", "")))

	token := NewToken("github_token", job.ID, []string{"contents:write"})
	token.State = StateHighValue
	require.NoError(t, p.AddAsset(token))
	require.NoError(t, p.AddRelationship(job.ID, token.ID, Exposes("build", "")))

	oidcToken := NewToken("oidc", job.ID, []string{"id_token"})
	oidcToken.State = StateHighValue
	oidcToken.SetProperty("provider", "aws")
	require.NoError(t, p.AddAsset(oidcToken))
	require.NoError(t, p.AddRelationship(job.ID, oidcToken.ID, Exposes("build", "")))

	return p
}

func TestTraceKillChain_RealisticGraph(t *testing.T) {
	p := buildRealisticGraph(t)

	vulnID := "vuln:injection:.github/workflows/ci.yml:45"
	chain, err := p.TraceKillChain(vulnID)
	require.NoError(t, err)

	assert.Equal(t, vulnID, chain.VulnID)
	assert.GreaterOrEqual(t, len(chain.Stages), 5, "should have org, repo, workflow, job, vuln stages")

	assert.Equal(t, StageEntry, chain.Stages[0].StageType)
	assert.Equal(t, AssetOrganization, chain.Stages[0].Asset.Type)

	var foundVuln, foundCred bool
	for _, s := range chain.Stages {
		if s.StageType == StageExploit && s.Asset.Type == AssetVulnerability {
			foundVuln = true
		}
		if s.StageType == StageCredential {
			foundCred = true
		}
	}
	assert.True(t, foundVuln, "should have vulnerability stage")
	assert.True(t, foundCred, "should have credential stages")

	assert.GreaterOrEqual(t, len(chain.Projections), 1, "should have pivot projections from AWS secret")
}

func TestTraceKillChain_DeadEndVuln(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	require.NoError(t, p.AddAsset(repo))

	wf := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	require.NoError(t, p.AddAsset(wf))
	require.NoError(t, p.AddRelationship(repo.ID, wf.ID, Contains()))

	vuln := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 10)
	require.NoError(t, p.AddAsset(vuln))
	require.NoError(t, p.AddRelationship(wf.ID, vuln.ID, VulnerableTo("injection", "critical")))

	chain, err := p.TraceKillChain(vuln.ID)
	require.NoError(t, err)

	assert.Empty(t, chain.Projections, "dead-end vuln should have no projections")
	assert.GreaterOrEqual(t, len(chain.Stages), 2, "should have repo, workflow, vuln")
}

func TestTraceKillChain_OrphanVuln(t *testing.T) {
	p := New()

	vuln := NewVulnerability("injection", "", "standalone.yml", 1)
	require.NoError(t, p.AddAsset(vuln))

	chain, err := p.TraceKillChain(vuln.ID)
	require.NoError(t, err)

	assert.Equal(t, vuln.ID, chain.VulnID)
	assert.Len(t, chain.Stages, 1, "orphan vuln should only have the vuln stage itself")
	assert.Empty(t, chain.Projections)
}

func TestTraceKillChain_NotFound(t *testing.T) {
	p := New()

	_, err := p.TraceKillChain("nonexistent")
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestTraceKillChain_ConfirmedStages(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	repo.State = StateExploited
	require.NoError(t, p.AddAsset(repo))

	vuln := NewVulnerability("injection", "", "ci.yml", 1)
	vuln.State = StateExploited
	require.NoError(t, p.AddAsset(vuln))
	require.NoError(t, p.AddRelationship(repo.ID, vuln.ID, VulnerableTo("injection", "critical")))

	chain, err := p.TraceKillChain(vuln.ID)
	require.NoError(t, err)

	for _, s := range chain.Stages {
		assert.True(t, s.Confirmed, "stage %s should be confirmed", s.Asset.Name)
	}
}

func TestGetPredecessors(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	wf := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("KEY", "scope", "github")

	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(wf))
	require.NoError(t, p.AddAsset(secret))
	require.NoError(t, p.AddRelationship(repo.ID, wf.ID, Contains()))
	require.NoError(t, p.AddRelationship(wf.ID, secret.ID, Exposes("", "")))

	preds := p.GetPredecessors(wf.ID)
	require.Len(t, preds, 1)
	assert.Equal(t, repo.ID, preds[0].ID)

	preds = p.GetPredecessors(secret.ID)
	require.Len(t, preds, 1)
	assert.Equal(t, wf.ID, preds[0].ID)

	preds = p.GetPredecessors(repo.ID)
	assert.Empty(t, preds, "root should have no predecessors")
}

func TestGetOutgoingEdges(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	wf := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("KEY", "scope", "github")

	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(wf))
	require.NoError(t, p.AddAsset(secret))
	require.NoError(t, p.AddRelationship(repo.ID, wf.ID, Contains()))
	require.NoError(t, p.AddRelationship(wf.ID, secret.ID, Exposes("deploy", "")))

	edges := p.GetOutgoingEdges(repo.ID)
	require.Len(t, edges, 1)
	assert.Equal(t, wf.ID, edges[0].To)
	assert.Equal(t, RelContains, edges[0].Relationship.Type)

	edges = p.GetOutgoingEdges(wf.ID)
	require.Len(t, edges, 1)
	assert.Equal(t, secret.ID, edges[0].To)
	assert.Equal(t, RelExposes, edges[0].Relationship.Type)

	edges = p.GetOutgoingEdges(secret.ID)
	assert.Empty(t, edges, "leaf should have no outgoing edges")
}

func TestReverseEdges_SurviveRemoveRelationship(t *testing.T) {
	p := New()

	a := NewRepository("acme", "api", "github")
	b := NewWorkflow(a.ID, "ci.yml")
	require.NoError(t, p.AddAsset(a))
	require.NoError(t, p.AddAsset(b))
	require.NoError(t, p.AddRelationship(a.ID, b.ID, Contains()))

	assert.Len(t, p.GetPredecessors(b.ID), 1)

	require.NoError(t, p.RemoveRelationship(a.ID, b.ID))
	assert.Empty(t, p.GetPredecessors(b.ID))
}

func TestReverseEdges_SurviveRemoveAsset(t *testing.T) {
	p := New()

	a := NewRepository("acme", "api", "github")
	b := NewWorkflow(a.ID, "ci.yml")
	c := NewSecret("KEY", "scope", "github")
	require.NoError(t, p.AddAsset(a))
	require.NoError(t, p.AddAsset(b))
	require.NoError(t, p.AddAsset(c))
	require.NoError(t, p.AddRelationship(a.ID, b.ID, Contains()))
	require.NoError(t, p.AddRelationship(b.ID, c.ID, Exposes("", "")))

	require.NoError(t, p.RemoveAsset(b.ID))
	assert.Empty(t, p.GetPredecessors(b.ID))
	assert.Empty(t, p.GetPredecessors(c.ID))
}

func TestReverseEdges_SurviveJSONRoundTrip(t *testing.T) {
	p := New()

	a := NewRepository("acme", "api", "github")
	b := NewWorkflow(a.ID, "ci.yml")
	require.NoError(t, p.AddAsset(a))
	require.NoError(t, p.AddAsset(b))
	require.NoError(t, p.AddRelationship(a.ID, b.ID, Contains()))

	data, err := p.MarshalJSON()
	require.NoError(t, err)

	p2 := New()
	require.NoError(t, p2.UnmarshalJSON(data))

	preds := p2.GetPredecessors(b.ID)
	require.Len(t, preds, 1)
	assert.Equal(t, a.ID, preds[0].ID)
}

func TestKillChain_CredentialCount(t *testing.T) {
	chain := KillChain{
		Stages: []KillChainStage{
			{StageType: StageEntry},
			{StageType: StageExploit},
			{StageType: StageCredential},
			{StageType: StageCredential},
		},
	}
	assert.Equal(t, 2, chain.CredentialCount())
}

func TestKillChain_CloudPivotCount(t *testing.T) {
	chain := KillChain{
		Projections: []PivotProjection{
			{Provider: "aws"},
			{Provider: "github"},
			{Provider: "gcp"},
		},
	}
	assert.Equal(t, 2, chain.CloudPivotCount())
}
