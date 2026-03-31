// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func TestDetectAppID_UsesPairedAppID(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "-----BEGIN RSA PRIVATE KEY-----",
			Type:        "github_app_key",
			PairedAppID: "99999",
		},
	}

	assert.Equal(t, "99999", m.detectAppID())
}

func TestDetectAppID_PairedAppIDTakesPriority(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"OTHER_APP_ID": "github_app_id",
	}
	m.lootStash = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "-----BEGIN RSA PRIVATE KEY-----",
			Type:        "github_app_key",
			PairedAppID: "paired-id",
		},
		{Name: "OTHER_APP_ID", Value: "structural-id"},
	}

	assert.Equal(t, "paired-id", m.detectAppID(), "PairedAppID should take priority over structural match")
}

func TestDetectAppID_StructuralMatch(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"WHOOLI_BOT_APP_PRIVATE_KEY": "github_app_key",
		"WHOOLI_BOT_APP_ID":          "github_app_id",
	}
	m.lootStash = []CollectedSecret{
		{Name: "WHOOLI_BOT_APP_PRIVATE_KEY", Value: "-----BEGIN RSA PRIVATE KEY-----", Type: "github_app_key"},
		{Name: "WHOOLI_BOT_APP_ID", Value: "12345", Type: "github_app_id"},
	}

	assert.Equal(t, "12345", m.detectAppID())
}

func TestDetectAppID_StructuralFromSessionLoot(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"MY_APP_IDENT": "github_app_id",
	}
	m.sessionLoot = []CollectedSecret{
		{Name: "MY_APP_IDENT", Value: "67890"},
	}

	assert.Equal(t, "67890", m.detectAppID())
}

func TestDetectAppID_HardcodedAppID(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "BOT_PEM", Value: "-----BEGIN RSA PRIVATE KEY-----", Type: "github_app_key"},
	}
	m.hardcodedAppIDs = []string{"98765"}

	assert.Equal(t, "98765", m.detectAppID())
}

func TestDetectAppID_HardcodedAfterStructural(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"MY_ID": "github_app_id",
	}
	m.lootStash = []CollectedSecret{
		{Name: "MY_ID", Value: "structural-id"},
	}
	m.hardcodedAppIDs = []string{"hardcoded-id"}

	assert.Equal(t, "structural-id", m.detectAppID(), "structural match should take priority over hardcoded")
}

func TestDetectAppID_FallsBackToHeuristic(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "SOME_GITHUB_APP_ID", Value: "99999"},
	}

	assert.Equal(t, "99999", m.detectAppID())
}

func TestDetectAppID_StructuralPreferredOverHeuristic(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"BANANA_ID": "github_app_id",
	}
	m.lootStash = []CollectedSecret{
		{Name: "BANANA_ID", Value: "structural-id"},
		{Name: "GITHUB_APP_ID", Value: "heuristic-id"},
	}

	assert.Equal(t, "structural-id", m.detectAppID())
}

func TestDetectAppID_EmptyLoot(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"SOME_KEY": "github_app_id",
	}

	assert.Empty(t, m.detectAppID())
}

func TestDetectAppID_TrimsWhitespace(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"APP_IDENT": "github_app_id",
	}
	m.lootStash = []CollectedSecret{
		{Name: "APP_IDENT", Value: "  42  "},
	}

	assert.Equal(t, "42", m.detectAppID())
}

func TestDetectAppID_SkipsEmptyValues(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.workflowSecretTypes = map[string]string{
		"EMPTY_ID": "github_app_id",
		"REAL_ID":  "github_app_id",
	}
	m.lootStash = []CollectedSecret{
		{Name: "EMPTY_ID", Value: ""},
		{Name: "REAL_ID", Value: "77777"},
	}

	assert.Equal(t, "77777", m.detectAppID())
}

func TestDetectAppID_HeuristicExcludesKeyAndPEM(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "APP_KEY", Value: "should-be-skipped"},
		{Name: "APP_PEM_ID", Value: "also-skipped"},
		{Name: "MY_APP_ID", Value: "correct"},
	}

	assert.Equal(t, "correct", m.detectAppID())
}

func TestExecuteGitHubPivot_TracksPrivateRepos(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghp_test123"}
	m.kitchenClient = &mockKitchenClient{
		listReposWithInfoResp: []counter.RepoInfo{
			{FullName: "acme/public-app", IsPrivate: false, CanPush: false},
			{FullName: "acme/secret-infra", IsPrivate: true, CanPush: true},
			{FullName: "acme/internal-tools", IsPrivate: true, CanPush: false},
			{FullName: "acme/docs", IsPrivate: false, CanPush: true},
		},
	}

	result := m.executeGitHubPivot("")

	assert.True(t, result.Success)
	assert.Equal(t, 4, result.TotalFound)
	assert.Len(t, result.NewRepos, 4)
	assert.Len(t, result.NewPrivateRepos, 2)
	assert.Contains(t, result.NewPrivateRepos, "acme/secret-infra")
	assert.Contains(t, result.NewPrivateRepos, "acme/internal-tools")
}

func TestExecuteGitHubPivot_RecordsVisibilityInKnownEntities(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghp_test456"}
	m.kitchenClient = &mockKitchenClient{
		listReposWithInfoResp: []counter.RepoInfo{
			{FullName: "org/private-repo", IsPrivate: true, CanPush: true},
			{FullName: "org/public-repo", IsPrivate: false, CanPush: false},
		},
	}

	result := m.executeGitHubPivot("")

	assert.True(t, result.Success)

	privateEntity := m.knownEntities["repo:org/private-repo"]
	assert.NotNil(t, privateEntity)
	assert.True(t, privateEntity.IsPrivate)
	assert.Contains(t, privateEntity.Permissions, "push")

	publicEntity := m.knownEntities["repo:org/public-repo"]
	assert.NotNil(t, publicEntity)
	assert.False(t, publicEntity.IsPrivate)
	assert.Empty(t, publicEntity.Permissions)
}

func TestExecuteGitHubPivot_SkipsAlreadyKnownRepos(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghp_test789"}
	m.knownEntities = map[string]*KnownEntity{
		"repo:acme/known-repo": {ID: "repo:acme/known-repo", EntityType: "repo", Name: "acme/known-repo"},
	}
	m.kitchenClient = &mockKitchenClient{
		listReposWithInfoResp: []counter.RepoInfo{
			{FullName: "acme/known-repo", IsPrivate: true, CanPush: true},
			{FullName: "acme/new-repo", IsPrivate: true, CanPush: false},
		},
	}

	result := m.executeGitHubPivot("")

	assert.True(t, result.Success)
	assert.Equal(t, 2, result.TotalFound)
	assert.Len(t, result.NewRepos, 1)
	assert.Equal(t, "acme/new-repo", result.NewRepos[0])
	assert.Len(t, result.NewPrivateRepos, 1)
	assert.Equal(t, "acme/new-repo", result.NewPrivateRepos[0])

	knownEntity := m.knownEntities["repo:acme/known-repo"]
	assert.True(t, knownEntity.IsPrivate, "existing entity should be updated with private visibility")
	assert.Contains(t, knownEntity.Permissions, "push", "existing entity should be updated with push permission")
}

func TestExecuteGitHubAppPivot_FindsPEMViaStructuralType(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.kitchenClient = &mockKitchenClient{
		listAppInstallationsErr: fmt.Errorf("list installations: mock error"),
	}
	m.workflowSecretTypes = map[string]string{
		"BANANA": "github_app_key",
	}
	m.lootStash = []CollectedSecret{
		{Name: "BANANA", Value: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----", Type: "private_key"},
	}

	result := m.executeGitHubAppPivot("12345")

	assert.False(t, result.Success)
	assert.Contains(t, result.Err.Error(), "list installations")
}

func TestExecuteGitHubAppPivot_FallsBackToTypeField(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.kitchenClient = &mockKitchenClient{
		listAppInstallationsErr: fmt.Errorf("list installations: mock error"),
	}
	m.lootStash = []CollectedSecret{
		{Name: "UNKNOWN_SECRET", Value: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----", Type: "github_app_key"},
	}

	result := m.executeGitHubAppPivot("12345")

	assert.False(t, result.Success)
	assert.Contains(t, result.Err.Error(), "list installations")
}

func TestExecuteGitHubAppPivot_NoPEM(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "SOME_TOKEN", Value: "ghp_xxx", Type: "github_pat"},
	}

	result := m.executeGitHubAppPivot("")

	assert.False(t, result.Success)
	assert.Contains(t, result.Err.Error(), "no GitHub App keys found")
}

func TestExecuteGitHubAppPivot_FindsPEMInSessionLoot(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.kitchenClient = &mockKitchenClient{
		listAppInstallationsErr: fmt.Errorf("list installations: mock error"),
	}
	m.workflowSecretTypes = map[string]string{
		"MY_PEM": "github_app_key",
	}
	m.sessionLoot = []CollectedSecret{
		{Name: "MY_PEM", Value: "-----BEGIN RSA PRIVATE KEY-----\nsession\n-----END RSA PRIVATE KEY-----", CollectedAt: time.Now()},
	}

	result := m.executeGitHubAppPivot("12345")

	assert.False(t, result.Success)
	assert.Contains(t, result.Err.Error(), "list installations")
}

func TestResolveGitHubAppPivot_RequiresSelectionWhenMultipleKeys(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "APP_KEY_ONE", Value: "pem-one", Type: "github_app_key", PairedAppID: "12345"},
		{Name: "APP_KEY_TWO", Value: "pem-two", Type: "github_app_key", PairedAppID: "12345"},
	}

	_, _, err := m.resolveGitHubAppPivot("12345")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple GitHub App keys")
}

func TestResolveGitHubAppPivot_UsesSelectedKey(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "APP_KEY_ONE", Value: "pem-one", Type: "github_app_key", PairedAppID: "12345"},
		{Name: "APP_KEY_TWO", Value: "pem-two", Type: "github_app_key", PairedAppID: "67890"},
	}
	selectLootSecretByName(t, &m, "APP_KEY_TWO")

	secret, appID, err := m.resolveGitHubAppPivot("")

	assert.NoError(t, err)
	assert.Equal(t, "APP_KEY_TWO", secret.Name)
	assert.Equal(t, "67890", appID)
}

func TestExecuteCommand_PivotGitHubUsesSelectedLootTokenTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.tokenInfo = &TokenInfo{Value: "ghp_initial", Type: DetectTokenType("ghp_initial")}
	m.kitchenClient = &mockKitchenClient{
		listReposWithInfoResp: []counter.RepoInfo{
			{FullName: "acme/api", IsPrivate: true},
			{FullName: "other/tooling", IsPrivate: true},
		},
	}
	m.lootStash = []CollectedSecret{
		{Name: "PIVOT_PAT", Value: "ghp_selected", Type: "github_pat", CollectedAt: time.Now()},
	}
	selectLootSecretByName(t, &m, "PIVOT_PAT")
	m.input.SetValue("pivot github acme")

	model, cmd := m.executeCommand()
	if assert.NotNil(t, cmd) {
		msg := cmd()
		result, ok := msg.(PivotResultMsg)
		if assert.True(t, ok) {
			assert.True(t, result.Success)
			assert.Equal(t, 1, result.TotalFound)
			assert.Equal(t, []string{"acme/api"}, result.NewRepos)
		}
	}
	assert.Equal(t, "ghp_selected", model.(Model).tokenInfo.Value)
}
