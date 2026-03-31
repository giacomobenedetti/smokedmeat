// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReconResult(t *testing.T) {
	result := NewReconResult("brisket-abc123")

	assert.Equal(t, "brisket-abc123", result.AgentID)
	assert.False(t, result.Timestamp.IsZero())
	assert.Equal(t, PlatformUnknown, result.Platform)
	assert.NotNil(t, result.Secrets)
	assert.Empty(t, result.Secrets)
	assert.NotNil(t, result.Errors)
	assert.Empty(t, result.Errors)
}

func TestReconResult_AddSecret(t *testing.T) {
	result := NewReconResult("agent-1")

	result.AddSecret("AWS_ACCESS_KEY_ID", SecretTypeAWS, 20, true)
	result.AddSecret("DATABASE_URL", SecretTypeDatabase, 100, false)

	assert.Len(t, result.Secrets, 2)

	// Check first secret
	assert.Equal(t, "AWS_ACCESS_KEY_ID", result.Secrets[0].Name)
	assert.Equal(t, SecretTypeAWS, result.Secrets[0].Type)
	assert.Equal(t, 20, result.Secrets[0].Length)
	assert.True(t, result.Secrets[0].HighValue)
	assert.Equal(t, "environment", result.Secrets[0].Source)

	// Check second secret
	assert.Equal(t, "DATABASE_URL", result.Secrets[1].Name)
	assert.Equal(t, SecretTypeDatabase, result.Secrets[1].Type)
	assert.False(t, result.Secrets[1].HighValue)
}

func TestReconResult_AddError(t *testing.T) {
	result := NewReconResult("agent-1")

	result.AddError("failed to detect platform")
	result.AddError("network check failed")

	assert.Len(t, result.Errors, 2)
	assert.Equal(t, "failed to detect platform", result.Errors[0])
	assert.Equal(t, "network check failed", result.Errors[1])
}

func TestReconResult_HasHighValueSecrets(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []DetectedSecret
		expected bool
	}{
		{
			name:     "no secrets",
			secrets:  []DetectedSecret{},
			expected: false,
		},
		{
			name: "only low-value secrets",
			secrets: []DetectedSecret{
				{Name: "API_KEY", Type: SecretTypeAPI, HighValue: false},
				{Name: "DB_URL", Type: SecretTypeDatabase, HighValue: false},
			},
			expected: false,
		},
		{
			name: "has high-value secret",
			secrets: []DetectedSecret{
				{Name: "API_KEY", Type: SecretTypeAPI, HighValue: false},
				{Name: "AWS_KEY", Type: SecretTypeAWS, HighValue: true},
			},
			expected: true,
		},
		{
			name: "all high-value secrets",
			secrets: []DetectedSecret{
				{Name: "AWS_KEY", Type: SecretTypeAWS, HighValue: true},
				{Name: "GCP_KEY", Type: SecretTypeGCP, HighValue: true},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewReconResult("agent-1")
			result.Secrets = tt.secrets
			assert.Equal(t, tt.expected, result.HasHighValueSecrets())
		})
	}
}

func TestReconResult_SecretCount(t *testing.T) {
	result := NewReconResult("agent-1")
	assert.Equal(t, 0, result.SecretCount())

	result.AddSecret("KEY1", SecretTypeGeneric, 10, false)
	assert.Equal(t, 1, result.SecretCount())

	result.AddSecret("KEY2", SecretTypeGeneric, 10, true)
	result.AddSecret("KEY3", SecretTypeGeneric, 10, false)
	assert.Equal(t, 3, result.SecretCount())
}

func TestReconResult_HighValueSecretCount(t *testing.T) {
	result := NewReconResult("agent-1")
	assert.Equal(t, 0, result.HighValueSecretCount())

	result.AddSecret("LOW1", SecretTypeGeneric, 10, false)
	assert.Equal(t, 0, result.HighValueSecretCount())

	result.AddSecret("HIGH1", SecretTypeAWS, 20, true)
	assert.Equal(t, 1, result.HighValueSecretCount())

	result.AddSecret("LOW2", SecretTypeDatabase, 50, false)
	result.AddSecret("HIGH2", SecretTypeGCP, 100, true)
	assert.Equal(t, 2, result.HighValueSecretCount())
}

func TestReconResult_MarshalUnmarshal(t *testing.T) {
	result := NewReconResult("brisket-test")
	result.Platform = PlatformGitHubActions
	result.Duration = 123.45

	result.Repository = &RepoInfo{
		FullName: "acme/api",
		Owner:    "acme",
		Name:     "api",
		Platform: PlatformGitHubActions,
	}

	result.Workflow = &WorkflowInfo{
		Name:  "CI",
		Path:  ".github/workflows/ci.yml",
		Job:   "build",
		Actor: "developer",
		Event: "push",
	}

	result.Runner = &RunnerInfo{
		Name:       "ubuntu-latest",
		OS:         "linux",
		Arch:       "amd64",
		Hostname:   "runner-1",
		SelfHosted: false,
	}

	result.OIDC = &OIDCInfo{
		Available: true,
		TokenURL:  "https://token.actions.githubusercontent.com",
	}

	result.AddSecret("AWS_KEY", SecretTypeAWS, 20, true)
	result.AddSecret("NPM_TOKEN", SecretTypeNPM, 36, true)

	// Marshal
	data, err := result.Marshal()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal
	decoded, err := UnmarshalReconResult(data)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, result.AgentID, decoded.AgentID)
	assert.Equal(t, result.Platform, decoded.Platform)
	assert.Equal(t, result.Duration, decoded.Duration)

	// Repository
	require.NotNil(t, decoded.Repository)
	assert.Equal(t, "acme/api", decoded.Repository.FullName)
	assert.Equal(t, "acme", decoded.Repository.Owner)

	// Workflow
	require.NotNil(t, decoded.Workflow)
	assert.Equal(t, "CI", decoded.Workflow.Name)
	assert.Equal(t, "build", decoded.Workflow.Job)
	assert.Equal(t, "push", decoded.Workflow.Event)

	// Runner
	require.NotNil(t, decoded.Runner)
	assert.Equal(t, "linux", decoded.Runner.OS)
	assert.False(t, decoded.Runner.SelfHosted)

	// OIDC
	require.NotNil(t, decoded.OIDC)
	assert.True(t, decoded.OIDC.Available)

	// Secrets
	assert.Len(t, decoded.Secrets, 2)
	assert.Equal(t, "AWS_KEY", decoded.Secrets[0].Name)
	assert.Equal(t, SecretTypeAWS, decoded.Secrets[0].Type)
}

func TestReconResult_UnmarshalInvalidJSON(t *testing.T) {
	_, err := UnmarshalReconResult([]byte("invalid json"))
	assert.Error(t, err)
}

func TestReconResult_UnmarshalEmptyJSON(t *testing.T) {
	result, err := UnmarshalReconResult([]byte("{}"))
	require.NoError(t, err)
	assert.Empty(t, result.AgentID)
	// Note: JSON unmarshal doesn't set defaults, so Platform is empty string
	assert.Empty(t, result.Platform)
}

func TestCIPlatform_Constants(t *testing.T) {
	// Verify platform constants are correct strings
	assert.Equal(t, CIPlatform("unknown"), PlatformUnknown)
	assert.Equal(t, CIPlatform("github_actions"), PlatformGitHubActions)
	assert.Equal(t, CIPlatform("gitlab_ci"), PlatformGitLabCI)
	assert.Equal(t, CIPlatform("azure_devops"), PlatformAzureDevOps)
	assert.Equal(t, CIPlatform("circleci"), PlatformCircleCI)
	assert.Equal(t, CIPlatform("jenkins"), PlatformJenkins)
	assert.Equal(t, CIPlatform("bitbucket"), PlatformBitbucket)
}

func TestSecretType_Constants(t *testing.T) {
	// Verify secret type constants
	assert.Equal(t, SecretType("generic"), SecretTypeGeneric)
	assert.Equal(t, SecretType("aws"), SecretTypeAWS)
	assert.Equal(t, SecretType("gcp"), SecretTypeGCP)
	assert.Equal(t, SecretType("azure"), SecretTypeAzure)
	assert.Equal(t, SecretType("github"), SecretTypeGitHub)
	assert.Equal(t, SecretType("npm"), SecretTypeNPM)
	assert.Equal(t, SecretType("docker"), SecretTypeDocker)
	assert.Equal(t, SecretType("ssh"), SecretTypeSSH)
	assert.Equal(t, SecretType("database"), SecretTypeDatabase)
	assert.Equal(t, SecretType("api"), SecretTypeAPI)
	assert.Equal(t, SecretType("oidc"), SecretTypeOIDC)
}

func TestDetectedSecret_Structure(t *testing.T) {
	secret := DetectedSecret{
		Name:      "AWS_ACCESS_KEY_ID",
		Type:      SecretTypeAWS,
		Length:    20,
		Prefix:    "AKIA",
		Source:    "environment",
		HighValue: true,
	}

	assert.Equal(t, "AWS_ACCESS_KEY_ID", secret.Name)
	assert.Equal(t, SecretTypeAWS, secret.Type)
	assert.Equal(t, 20, secret.Length)
	assert.Equal(t, "AKIA", secret.Prefix)
	assert.Equal(t, "environment", secret.Source)
	assert.True(t, secret.HighValue)
}

func TestRepoInfo_Structure(t *testing.T) {
	repo := RepoInfo{
		FullName:      "org/repo",
		Owner:         "org",
		Name:          "repo",
		Platform:      PlatformGitHubActions,
		DefaultBranch: "main",
		Permissions:   map[string]string{"contents": "write"},
	}

	// Verify all fields
	assert.Equal(t, "org/repo", repo.FullName)
	assert.Equal(t, "org", repo.Owner)
	assert.Equal(t, "repo", repo.Name)
	assert.Equal(t, PlatformGitHubActions, repo.Platform)
	assert.Equal(t, "main", repo.DefaultBranch)
	assert.Equal(t, "write", repo.Permissions["contents"])
}

func TestWorkflowInfo_Structure(t *testing.T) {
	wf := WorkflowInfo{
		Name:      "CI",
		Path:      ".github/workflows/ci.yml",
		RunID:     "12345",
		RunNumber: "42",
		Job:       "build",
		Actor:     "developer",
		Event:     "pull_request",
		Ref:       "refs/pull/123/merge",
		SHA:       "abc123def456",
	}

	// Verify all fields
	assert.Equal(t, "CI", wf.Name)
	assert.Equal(t, ".github/workflows/ci.yml", wf.Path)
	assert.Equal(t, "12345", wf.RunID)
	assert.Equal(t, "42", wf.RunNumber)
	assert.Equal(t, "build", wf.Job)
	assert.Equal(t, "developer", wf.Actor)
	assert.Equal(t, "pull_request", wf.Event)
	assert.Equal(t, "refs/pull/123/merge", wf.Ref)
	assert.Equal(t, "abc123def456", wf.SHA)
}

func TestOIDCInfo_Structure(t *testing.T) {
	oidc := OIDCInfo{
		Available:    true,
		TokenURL:     "https://token.example.com",
		RequestURL:   "https://request.example.com",
		RequestToken: "tok_...",
		Claims:       map[string]string{"sub": "repo:org/repo"},
	}

	// Verify all fields
	assert.True(t, oidc.Available)
	assert.Equal(t, "https://token.example.com", oidc.TokenURL)
	assert.Equal(t, "https://request.example.com", oidc.RequestURL)
	assert.Equal(t, "tok_...", oidc.RequestToken)
	assert.Equal(t, "repo:org/repo", oidc.Claims["sub"])
}

func TestRunnerInfo_Structure(t *testing.T) {
	runner := RunnerInfo{
		Name:       "self-hosted-1",
		OS:         "linux",
		Arch:       "amd64",
		Hostname:   "runner.internal",
		SelfHosted: true,
		Container:  false,
		ToolCache:  "/opt/hostedtoolcache",
		Workspace:  "/home/runner/work",
		TempDir:    "/tmp",
	}

	// Verify all fields
	assert.Equal(t, "self-hosted-1", runner.Name)
	assert.Equal(t, "linux", runner.OS)
	assert.Equal(t, "amd64", runner.Arch)
	assert.Equal(t, "runner.internal", runner.Hostname)
	assert.True(t, runner.SelfHosted)
	assert.False(t, runner.Container)
	assert.Equal(t, "/opt/hostedtoolcache", runner.ToolCache)
	assert.Equal(t, "/home/runner/work", runner.Workspace)
	assert.Equal(t, "/tmp", runner.TempDir)
}

func TestNetworkInfo_Structure(t *testing.T) {
	net := NetworkInfo{
		Interfaces:       []string{"eth0", "docker0"},
		CanReachInternet: true,
		ProxyConfigured:  false,
	}

	assert.Len(t, net.Interfaces, 2)
	assert.True(t, net.CanReachInternet)
	assert.False(t, net.ProxyConfigured)
}
