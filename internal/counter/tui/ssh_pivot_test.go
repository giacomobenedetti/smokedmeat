// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSSHPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func selectLootSecretByName(t *testing.T, m *Model, name string) {
	t.Helper()
	m.RebuildLootTree()
	for _, node := range m.lootTreeNodes {
		if node.HasChildren() {
			node.Expanded = true
		}
	}
	m.ReflattenLootTree()
	for i, node := range m.lootTreeNodes {
		secret := m.getLootSecret(node)
		if secret != nil && secret.Name == name {
			m.lootTreeCursor = i
			return
		}
	}
	t.Fatalf("secret %s not found in loot tree", name)
}

func TestCollectedSecret_CanUseAsSSHKey(t *testing.T) {
	key := testSSHPrivateKey(t)

	assert.True(t, CollectedSecret{Type: "private_key", Value: key}.CanUseAsSSHKey())
	assert.True(t, CollectedSecret{Type: "private_key", Value: "```pem\n" + key + "\n```"}.CanUseAsSSHKey())
	assert.False(t, CollectedSecret{Type: "github_app_key", Value: key}.CanUseAsSSHKey())
	assert.False(t, CollectedSecret{Type: "private_key", Value: "not-a-key"}.CanUseAsSSHKey())
}

func TestCredentialRecommendations_SSHKey(t *testing.T) {
	key := testSSHPrivateKey(t)

	recs := credentialRecommendations(CollectedSecret{
		Name:       "DEPLOY_KEY",
		Type:       "private_key",
		Value:      key,
		Repository: "acme/source",
	}, 0)

	require.Len(t, recs, 1)
	assert.Equal(t, "pivot ssh", recs[0].Command)
	assert.Contains(t, recs[0].Description, "read/write access")
}

func TestGetCompletions_ListsPivotSSH(t *testing.T) {
	m := NewModel(Config{})
	m.phase = PhaseRecon

	completions := m.getCompletions("pivot s")

	assert.Contains(t, completions, "pivot ssh")
}

func TestGetCompletions_ListsExplicitSSHPivotScopes(t *testing.T) {
	m := NewModel(Config{})
	m.phase = PhaseRecon
	m.targetType = "org"
	m.target = "acme"

	completions := m.getCompletions("pivot ssh ")

	assert.Contains(t, completions, "pivot ssh org:")
	assert.Contains(t, completions, "pivot ssh repo:")
	assert.Contains(t, completions, "pivot ssh org:acme")
}

func TestExecuteSSHPivot_RequiresSelectionWhenMultipleKeys(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()

	var probedMu sync.Mutex
	var probed []string
	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		probedMu.Lock()
		probed = append(probed, repo)
		probedMu.Unlock()
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "read"}
	})

	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{
			Name:        "OLD_KEY",
			Type:        "private_key",
			Value:       key,
			Repository:  "acme/source",
			CollectedAt: time.Now().Add(-time.Hour),
		},
		{
			Name:        "DEPLOY_KEY",
			Type:        "private_key",
			Value:       key,
			Repository:  "acme/source",
			CollectedAt: time.Now(),
		},
	}
	m.knownEntities["repo:acme/private-infra"] = &KnownEntity{ID: "repo:acme/private-infra", EntityType: "repo", Name: "acme/private-infra", IsPrivate: true}
	m.knownEntities["repo:acme/public-site"] = &KnownEntity{ID: "repo:acme/public-site", EntityType: "repo", Name: "acme/public-site", IsPrivate: false}
	m.knownEntities["repo:other/secret"] = &KnownEntity{ID: "repo:other/secret", EntityType: "repo", Name: "other/secret", IsPrivate: true}

	result := m.executeSSHPivot("")

	require.False(t, result.Success)
	assert.Contains(t, result.Err.Error(), "multiple SSH private keys")
	assert.Empty(t, probed)
}

func TestExecuteSSHPivot_UsesCurrentTargetOrg(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()

	var probedMu sync.Mutex
	var probed []string
	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		probedMu.Lock()
		probed = append(probed, repo)
		probedMu.Unlock()
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "read"}
	})

	m := NewModel(Config{SessionID: "test"})
	m.targetType = "org"
	m.target = "acme"
	m.lootStash = []CollectedSecret{
		{
			Name:        "OLD_KEY",
			Type:        "private_key",
			Value:       key,
			Repository:  "other/source",
			CollectedAt: time.Now().Add(-time.Hour),
		},
		{
			Name:        "DEPLOY_KEY",
			Type:        "private_key",
			Value:       key,
			Repository:  "acme/source",
			CollectedAt: time.Now(),
		},
	}
	m.knownEntities["repo:acme/private-infra"] = &KnownEntity{ID: "repo:acme/private-infra", EntityType: "repo", Name: "acme/private-infra", IsPrivate: true}
	m.knownEntities["repo:acme/public-site"] = &KnownEntity{ID: "repo:acme/public-site", EntityType: "repo", Name: "acme/public-site", IsPrivate: false}
	m.knownEntities["repo:other/secret"] = &KnownEntity{ID: "repo:other/secret", EntityType: "repo", Name: "other/secret", IsPrivate: true}
	selectLootSecretByName(t, &m, "DEPLOY_KEY")

	result := m.executeSSHPivot("")

	require.True(t, result.Success)
	assert.Equal(t, "DEPLOY_KEY", result.KeyName)
	assert.ElementsMatch(t, []string{"acme/private-infra", "acme/public-site"}, probed)
	require.Len(t, result.SSHResults, 2)
	assert.Equal(t, "acme/private-infra", result.SSHResults[0].Repo)
	assert.Equal(t, "acme/public-site", result.SSHResults[1].Repo)
}

func TestRunSSHPivot_ProbesReposConcurrently(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	prevTimeout := currentSSHPivotProbeTimeout()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()
	defer func() { setSSHPivotProbeTimeout(prevTimeout) }()

	var active atomic.Int32
	var maxActive atomic.Int32
	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		current := active.Add(1)
		for {
			seen := maxActive.Load()
			if current <= seen || maxActive.CompareAndSwap(seen, current) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		active.Add(-1)
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "read"}
	})

	m := NewModel(Config{SessionID: "test"})
	for _, repo := range []string{
		"acme/app-one",
		"acme/app-two",
		"acme/app-three",
		"acme/app-four",
	} {
		m.knownEntities["repo:"+repo] = &KnownEntity{ID: "repo:" + repo, EntityType: "repo", Name: repo, IsPrivate: true}
	}

	result := m.runSSHPivot(CollectedSecret{
		Name:  "DEPLOY_KEY",
		Type:  "private_key",
		Value: key,
	}, "org:acme")

	require.True(t, result.Success)
	require.Len(t, result.SSHResults, 4)
	assert.Greater(t, maxActive.Load(), int32(1))
	assert.Equal(t, "acme/app-four", result.SSHResults[0].Repo)
	assert.Equal(t, "acme/app-one", result.SSHResults[1].Repo)
	assert.Equal(t, "acme/app-three", result.SSHResults[2].Repo)
	assert.Equal(t, "acme/app-two", result.SSHResults[3].Repo)
}

func TestRunSSHPivot_ProbeTimeoutReturnsPromptly(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	prevTimeout := currentSSHPivotProbeTimeout()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()
	defer func() { setSSHPivotProbeTimeout(prevTimeout) }()

	block := make(chan struct{})
	setSSHPivotProbeTimeout(20 * time.Millisecond)
	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		<-block
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "read"}
	})

	m := NewModel(Config{SessionID: "test"})
	m.knownEntities["repo:acme/infrastructure-definitions"] = &KnownEntity{
		ID:         "repo:acme/infrastructure-definitions",
		EntityType: "repo",
		Name:       "acme/infrastructure-definitions",
		IsPrivate:  true,
	}

	start := time.Now()
	result := m.runSSHPivot(CollectedSecret{
		Name:  "DEPLOY_KEY",
		Type:  "private_key",
		Value: key,
	}, "repo:acme/infrastructure-definitions")
	close(block)

	require.True(t, result.Success)
	require.Len(t, result.SSHResults, 1)
	assert.False(t, result.SSHResults[0].Success)
	assert.Contains(t, result.SSHResults[0].Error, "probe timed out")
	assert.Less(t, time.Since(start), 300*time.Millisecond)
}

func TestRunSSHPivot_TracksWritePermissionOnKnownRepo(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()

	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "write"}
	})

	m := NewModel(Config{SessionID: "test"})
	m.knownEntities["repo:acme/infrastructure-definitions"] = &KnownEntity{
		ID:         "repo:acme/infrastructure-definitions",
		EntityType: "repo",
		Name:       "acme/infrastructure-definitions",
		IsPrivate:  true,
	}

	result := m.runSSHPivot(CollectedSecret{
		Name:  "DEPLOY_KEY",
		Type:  "private_key",
		Value: key,
	}, "repo:acme/infrastructure-definitions")

	require.True(t, result.Success)
	require.Len(t, result.NewPerms, 1)
	assert.Equal(t, "acme/infrastructure-definitions", result.NewPerms[0].Repo)
	assert.Contains(t, m.knownEntities["repo:acme/infrastructure-definitions"].Permissions, "push")
	assert.Equal(t, "write", m.knownEntities["repo:acme/infrastructure-definitions"].SSHPermission)
	assert.Equal(t, "write", result.SSHResults[0].Permission)
}

func TestExecuteSSHPivot_UsesCurrentTargetRepo(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()

	var probedMu sync.Mutex
	var probed []string
	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		probedMu.Lock()
		probed = append(probed, repo)
		probedMu.Unlock()
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "write"}
	})

	m := NewModel(Config{SessionID: "test"})
	m.targetType = "repo"
	m.target = "acme/infrastructure-definitions"
	m.lootStash = []CollectedSecret{
		{
			Name:        "DEPLOY_KEY",
			Type:        "private_key",
			Value:       key,
			Repository:  "acme/source",
			CollectedAt: time.Now(),
		},
	}
	m.knownEntities["repo:acme/infrastructure-definitions"] = &KnownEntity{
		ID:         "repo:acme/infrastructure-definitions",
		EntityType: "repo",
		Name:       "acme/infrastructure-definitions",
		IsPrivate:  true,
	}
	selectLootSecretByName(t, &m, "DEPLOY_KEY")

	result := m.executeSSHPivot("")

	require.True(t, result.Success)
	assert.Equal(t, []string{"acme/infrastructure-definitions"}, probed)
	require.Len(t, result.SSHResults, 1)
	assert.Equal(t, "acme/infrastructure-definitions", result.SSHResults[0].Repo)
}

func TestActivateSelectedSSHSecret_ActivatesKeyWithoutProbe(t *testing.T) {
	key := testSSHPrivateKey(t)

	m := NewModel(Config{SessionID: "test"})
	m.targetType = "repo"
	m.target = "acme/infrastructure-definitions"

	err := m.activateSelectedSSHSecret(CollectedSecret{
		Name:  "DEPLOY_KEY",
		Type:  "private_key",
		Value: key,
	})

	require.NoError(t, err)
	require.NotNil(t, m.sshState)
	assert.Equal(t, "DEPLOY_KEY", m.sshState.KeyName)
	assert.Equal(t, "repo:acme/infrastructure-definitions", m.sshState.Scope)
	assert.Equal(t, normalizeSSHPrivateKey(key), m.sshState.KeyValue)
}

func TestRunSSHPivot_AddsOperatorSuppliedRepoOnSuccess(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()

	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "read"}
	})

	m := NewModel(Config{SessionID: "test"})

	result := m.runSSHPivot(CollectedSecret{
		Name:  "DEPLOY_KEY",
		Type:  "private_key",
		Value: key,
	}, "repo:acme/guessed-repo")

	require.True(t, result.Success)
	assert.Equal(t, []string{"acme/guessed-repo"}, result.NewRepos)
	require.Contains(t, m.knownEntities, "repo:acme/guessed-repo")
	assert.Equal(t, "read", m.knownEntities["repo:acme/guessed-repo"].SSHPermission)
	assert.False(t, m.knownEntities["repo:acme/guessed-repo"].IsPrivate)
}

func TestExecuteCommand_PivotSSHDoesNotRequireDwell(t *testing.T) {
	key := testSSHPrivateKey(t)
	prevProbe := currentSSHProbeGitHubRepoFn()
	defer func() { setSSHProbeGitHubRepoFn(prevProbe) }()

	setSSHProbeGitHubRepoFn(func(_ string, repo string) SSHTrialResult {
		return SSHTrialResult{Host: "github.com", Repo: repo, Success: true, Permission: "read"}
	})

	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.targetType = "org"
	m.target = "acme"
	m.lootStash = []CollectedSecret{
		{Name: "DEPLOY_KEY", Type: "private_key", Value: key, Repository: "acme/source", CollectedAt: time.Now()},
	}
	m.knownEntities["repo:acme/private-infra"] = &KnownEntity{ID: "repo:acme/private-infra", EntityType: "repo", Name: "acme/private-infra", IsPrivate: true}
	m.input.SetValue("pivot ssh")

	_, cmd := m.executeCommand()
	require.NotNil(t, cmd)

	msg := cmd()
	result, ok := msg.(PivotResultMsg)
	require.True(t, ok)
	assert.True(t, result.Success)
	assert.Equal(t, PivotTypeSSHKey, result.Type)
}

func TestExecuteCommand_PivotSSHRejectsLegacyShorthand(t *testing.T) {
	key := testSSHPrivateKey(t)
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.lootStash = []CollectedSecret{
		{Name: "DEPLOY_KEY", Type: "private_key", Value: key, Repository: "acme/source", CollectedAt: time.Now()},
	}
	m.input.SetValue("pivot ssh acme")

	result, cmd := m.executeCommand()

	assert.Nil(t, cmd)
	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "use org:<owner> or repo:<owner/repo>")
}

func TestModelUpdate_SSHPivotStoresSecretMetadata(t *testing.T) {
	key := testSSHPrivateKey(t)
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "DEPLOY_KEY", Type: "private_key", Value: key},
	}

	result, _ := m.Update(PivotResultMsg{
		Type:     PivotTypeSSHKey,
		Success:  true,
		KeyName:  "DEPLOY_KEY",
		KeyValue: key,
		KeyType:  "ssh-rsa",
		KeyFP:    "SHA256:test",
		SSHResults: []SSHTrialResult{
			{Host: "github.com", Repo: "acme/infrastructure-definitions", Success: true, Permission: "write"},
		},
	})

	model := result.(Model)
	require.Len(t, model.lootStash, 1)
	assert.Equal(t, "ssh-rsa", model.lootStash[0].KeyType)
	assert.Equal(t, "SHA256:test", model.lootStash[0].KeyFingerprint)
	assert.True(t, model.lootStash[0].TrialsComplete)
	require.Len(t, model.lootStash[0].TrialResults, 1)
	assert.Equal(t, "write", model.lootStash[0].TrialResults[0].Permission)
	require.NotNil(t, model.sshState)
	assert.Equal(t, "DEPLOY_KEY", model.sshState.KeyName)
	assert.Equal(t, "github.com", model.sshState.Results[0].Host)
}
