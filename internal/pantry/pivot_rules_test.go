// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectPivots_AWSSecret(t *testing.T) {
	asset := NewSecret("AWS_ACCESS_KEY_ID", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "aws", projections[0].Provider)
	assert.Contains(t, projections[0].Actions, "Check STS identity")
}

func TestProjectPivots_GCPSecret(t *testing.T) {
	asset := NewSecret("GCP_SERVICE_ACCOUNT_KEY", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "gcp", projections[0].Provider)
	assert.Contains(t, projections[0].Actions, "List GCS buckets")
}

func TestProjectPivots_GoogleSecret(t *testing.T) {
	asset := NewSecret("GOOGLE_CREDENTIALS", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "gcp", projections[0].Provider)
}

func TestProjectPivots_AzureSecret(t *testing.T) {
	asset := NewSecret("AZURE_CLIENT_SECRET", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "azure", projections[0].Provider)
	assert.Contains(t, projections[0].Actions, "List resource groups")
}

func TestProjectPivots_NPMToken(t *testing.T) {
	asset := NewSecret("NPM_TOKEN", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "npm", projections[0].Provider)
	assert.Contains(t, projections[0].Actions, "Publish package (supply chain)")
}

func TestProjectPivots_GitHubAppKey(t *testing.T) {
	tests := []struct {
		name       string
		secretName string
	}{
		{"APP_KEY", "GITHUB_APP_KEY"},
		{"APP_PEM", "GH_APP_PEM"},
		{"APP_PRIVATE", "MY_APP_PRIVATE_KEY"},
		{"GITHUB_APP_KEY", "GITHUB_APP_KEY_FILE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := NewSecret(tt.secretName, "job1", "github")
			projections := ProjectPivots(asset)
			require.Len(t, projections, 1)
			assert.Equal(t, "github_app_key", projections[0].CredentialType)
			assert.Equal(t, "github", projections[0].Provider)
			assert.Contains(t, projections[0].Commands, "pivot app")
		})
	}
}

func TestProjectPivots_SSHKey(t *testing.T) {
	asset := NewSecret("SSH_PRIVATE_KEY", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "ssh", projections[0].Provider)
}

func TestProjectPivots_SigningKey(t *testing.T) {
	asset := NewSecret("SIGNING_KEY", "job1", "github")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "signing", projections[0].Provider)
}

func TestProjectPivots_UnknownSecret(t *testing.T) {
	asset := NewSecret("SOME_RANDOM_VAR", "job1", "github")
	projections := ProjectPivots(asset)
	assert.Empty(t, projections)
}

func TestProjectPivots_OIDCToken_AWS(t *testing.T) {
	asset := NewToken("oidc", "job1", []string{"id_token"})
	asset.SetProperty("provider", "aws")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "aws", projections[0].Provider)
	assert.Contains(t, projections[0].Actions, "STS AssumeRoleWithWebIdentity")
}

func TestProjectPivots_OIDCToken_GCP(t *testing.T) {
	asset := NewToken("oidc", "job1", []string{"id_token"})
	asset.SetProperty("provider", "gcp")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "gcp", projections[0].Provider)
}

func TestProjectPivots_OIDCToken_Azure(t *testing.T) {
	asset := NewToken("oidc", "job1", []string{"id_token"})
	asset.SetProperty("provider", "azure")
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "azure", projections[0].Provider)
}

func TestProjectPivots_OIDCToken_Unknown(t *testing.T) {
	asset := NewToken("oidc", "job1", []string{"id_token"})
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "cloud", projections[0].Provider)
}

func TestProjectPivots_GitHubToken_ContentsWrite(t *testing.T) {
	asset := NewToken("github_token", "job1", []string{"contents:write"})
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Equal(t, "github", projections[0].Provider)
	assert.Contains(t, projections[0].Actions[0], "contents:write")
}

func TestProjectPivots_GitHubToken_ActionsWrite(t *testing.T) {
	asset := NewToken("github_token", "job1", []string{"actions:write"})
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Contains(t, projections[0].Actions, "Dispatch workflows via actions:write")
}

func TestProjectPivots_GitHubToken_NoUsefulScopes(t *testing.T) {
	asset := NewToken("github_token", "job1", []string{"metadata:read"})
	projections := ProjectPivots(asset)
	assert.Empty(t, projections)
}

func TestProjectPivots_GitHubToken_JSONDeserializedScopes(t *testing.T) {
	asset := NewToken("github_token", "job1", nil)
	asset.Properties["scopes"] = []interface{}{"contents:write", "actions:read"}
	projections := ProjectPivots(asset)
	require.Len(t, projections, 1)
	assert.Contains(t, projections[0].Actions[0], "contents:write")
}

func TestProjectPivots_NonCredentialAsset(t *testing.T) {
	asset := NewRepository("acme", "api", "github")
	projections := ProjectPivots(asset)
	assert.Empty(t, projections)
}
