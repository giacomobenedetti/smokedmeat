// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenVault_ToCollectedSecrets(t *testing.T) {
	now := time.Now()
	vault := &TokenVault{
		Tokens: []VaultToken{
			{Name: "PAT1", Value: "ghp_abc", Source: "env", Scopes: []string{"repo"}, CollectedAt: now},
			{Name: "PAT2", Value: "ghp_def", Source: "loot", CollectedAt: now},
		},
	}

	secrets := vault.ToCollectedSecrets()
	require.Len(t, secrets, 2)
	assert.Equal(t, "PAT1", secrets[0].Name)
	assert.Equal(t, "ghp_abc", secrets[0].Value)
	assert.Equal(t, []string{"repo"}, secrets[0].Scopes)
	assert.Equal(t, "PAT2", secrets[1].Name)
}

func TestTokenVault_ToCollectedSecrets_Dedup(t *testing.T) {
	vault := &TokenVault{
		Tokens: []VaultToken{
			{Name: "PAT1", Value: "ghp_abc"},
			{Name: "PAT1", Value: "ghp_abc"},
			{Name: "PAT1", Value: "ghp_different"},
		},
	}

	secrets := vault.ToCollectedSecrets()
	assert.Len(t, secrets, 2)
}

func TestTokenVault_ToCollectedSecrets_Empty(t *testing.T) {
	vault := &TokenVault{}
	secrets := vault.ToCollectedSecrets()
	assert.Empty(t, secrets)
}

func TestFromCollectedSecrets(t *testing.T) {
	now := time.Now()
	secrets := []CollectedSecret{
		{Name: "PAT1", Value: "ghp_abc", Source: "env", Scopes: []string{"repo"}, CollectedAt: now},
		{Name: "KEY", Value: "AKIA123", Source: "loot", CollectedAt: now},
	}

	vault := FromCollectedSecrets(secrets)
	require.Len(t, vault.Tokens, 2)
	assert.Equal(t, "PAT1", vault.Tokens[0].Name)
	assert.Equal(t, "ghp_abc", vault.Tokens[0].Value)
	assert.NotZero(t, vault.UpdatedAt)
}

func TestFromCollectedSecrets_FiltersEphemeral(t *testing.T) {
	secrets := []CollectedSecret{
		{Name: "GITHUB_TOKEN", Value: "ghs_abc"},
		{Name: "PAT1", Value: "ghp_abc"},
		{Name: "ACTIONS_RUNTIME_TOKEN", Value: "xxx"},
	}

	vault := FromCollectedSecrets(secrets)
	require.Len(t, vault.Tokens, 1)
	assert.Equal(t, "PAT1", vault.Tokens[0].Name)
}

func TestFromCollectedSecrets_FiltersExpressMode(t *testing.T) {
	secrets := []CollectedSecret{
		{Name: "PAT_EXPRESS", Value: "ghp_express", ExpressMode: true},
		{Name: "PAT_DWELL", Value: "ghp_dwell"},
	}

	vault := FromCollectedSecrets(secrets)
	require.Len(t, vault.Tokens, 1)
	assert.Equal(t, "PAT_DWELL", vault.Tokens[0].Name)
}

func TestFromCollectedSecrets_Dedup(t *testing.T) {
	secrets := []CollectedSecret{
		{Name: "PAT1", Value: "ghp_abc"},
		{Name: "PAT1", Value: "ghp_abc"},
	}

	vault := FromCollectedSecrets(secrets)
	assert.Len(t, vault.Tokens, 1)
}

func TestFromCollectedSecrets_Empty(t *testing.T) {
	vault := FromCollectedSecrets(nil)
	assert.Empty(t, vault.Tokens)
	assert.NotZero(t, vault.UpdatedAt)
}

func TestTokenVault_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := []CollectedSecret{
		{Name: "PAT1", Value: "ghp_abc", Source: "env", Scopes: []string{"repo", "workflow"}, CollectedAt: now},
		{Name: "KEY", Value: "secret123", Source: "loot", CollectedAt: now},
	}

	vault := FromCollectedSecrets(original)
	recovered := vault.ToCollectedSecrets()

	require.Len(t, recovered, 2)
	assert.Equal(t, original[0].Name, recovered[0].Name)
	assert.Equal(t, original[0].Value, recovered[0].Value)
	assert.Equal(t, original[0].Scopes, recovered[0].Scopes)
	assert.Equal(t, original[1].Name, recovered[1].Name)
}

func TestTokenVault_RoundTrip_AllFields(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "-----BEGIN RSA PRIVATE KEY-----\ntest",
			Source:      "agent:abc:env",
			Type:        "github_app_key",
			CollectedAt: now,
			Repository:  "whooli/xyz",
			Workflow:    "whooli-analyzer.yml",
			Job:         "analyze",
			AgentID:     "abc12345",
			PairedAppID: "12345",
		},
	}

	vault := FromCollectedSecrets(original)
	recovered := vault.ToCollectedSecrets()

	require.Len(t, recovered, 1)
	r := recovered[0]
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", r.Name)
	assert.Equal(t, "github_app_key", r.Type)
	assert.Equal(t, "whooli/xyz", r.Repository)
	assert.Equal(t, "whooli-analyzer.yml", r.Workflow)
	assert.Equal(t, "analyze", r.Job)
	assert.Equal(t, "abc12345", r.AgentID)
	assert.Equal(t, "12345", r.PairedAppID)
}
