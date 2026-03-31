// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialRecommendations_GitHubPAT(t *testing.T) {
	secret := CollectedSecret{
		Name: "GITHUB_PAT",
		Type: "github_pat",
	}
	recs := credentialRecommendations(secret, 47)
	require.GreaterOrEqual(t, len(recs), 1)
	assert.Contains(t, recs[0].Label, "47")
	assert.Equal(t, "pivot github", recs[0].Command)
}

func TestCredentialRecommendations_GitHubToken(t *testing.T) {
	secret := CollectedSecret{
		Name:        "GITHUB_TOKEN",
		Type:        "github_token",
		BoundToRepo: "acme/webapp",
	}
	recs := credentialRecommendations(secret, 0)
	require.GreaterOrEqual(t, len(recs), 1)
	assert.Contains(t, recs[0].Label, "acme/webapp")
}

func TestCredentialRecommendations_GitHubTokenActionsWrite(t *testing.T) {
	secret := CollectedSecret{
		Name:   "GITHUB_TOKEN",
		Type:   "github_token",
		Scopes: []string{"actions:write", "contents:read"},
	}
	recs := credentialRecommendations(secret, 0)
	var hasDispatch bool
	for _, r := range recs {
		if r.Command == "pivot dispatch" {
			hasDispatch = true
		}
	}
	assert.True(t, hasDispatch, "should recommend dispatch with actions:write")
}

func TestCredentialRecommendations_AWS(t *testing.T) {
	secret := CollectedSecret{
		Name: "AWS_ACCESS_KEY_ID",
		Type: "aws_access_key",
	}
	recs := credentialRecommendations(secret, 0)
	require.GreaterOrEqual(t, len(recs), 1)
	assert.Contains(t, recs[0].Label, "S3")
}

func TestCredentialRecommendations_Azure(t *testing.T) {
	secret := CollectedSecret{
		Name: "AZURE_CLIENT_SECRET",
		Type: "azure",
	}
	recs := credentialRecommendations(secret, 0)
	require.Len(t, recs, 1)
	assert.Contains(t, recs[0].Label, "resource groups")
}

func TestCredentialRecommendations_GCP(t *testing.T) {
	secret := CollectedSecret{
		Name: "GCP_KEY",
		Type: "gcp",
	}
	recs := credentialRecommendations(secret, 0)
	require.Len(t, recs, 1)
	assert.Contains(t, recs[0].Label, "GCP")
}

func TestCredentialRecommendations_NPM(t *testing.T) {
	secret := CollectedSecret{
		Name: "NPM_TOKEN",
		Type: "npm",
	}
	recs := credentialRecommendations(secret, 0)
	require.Len(t, recs, 1)
	assert.Contains(t, recs[0].Label, "npm")
}

func TestCredentialRecommendations_UnknownType(t *testing.T) {
	secret := CollectedSecret{
		Name: "RANDOM_VAR",
		Type: "unknown",
	}
	recs := credentialRecommendations(secret, 0)
	assert.Empty(t, recs)
}

func TestCredentialRecommendations_AppToken(t *testing.T) {
	secret := CollectedSecret{
		Name: "APP_TOKEN",
		Type: "github_app_token",
	}
	recs := credentialRecommendations(secret, 0)
	require.GreaterOrEqual(t, len(recs), 1)
	assert.Contains(t, recs[0].Label, "installations")
}

func TestCredentialRecommendations_GitHubAppKey(t *testing.T) {
	secret := CollectedSecret{
		Name: "GITHUB_APP_PRIVATE_KEY",
		Type: "github_app_key",
	}
	recs := credentialRecommendations(secret, 0)
	require.Len(t, recs, 1)
	assert.Contains(t, recs[0].Label, "PEM")
	assert.Equal(t, "pivot app", recs[0].Command)
}

func TestCredentialRecommendations_SigningKey(t *testing.T) {
	secret := CollectedSecret{
		Name: "SIGNING_KEY",
		Type: "signing_key",
	}
	recs := credentialRecommendations(secret, 0)
	require.Len(t, recs, 1)
	assert.Contains(t, recs[0].Label, "Sign")
}
