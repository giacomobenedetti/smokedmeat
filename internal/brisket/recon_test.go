// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

// Helper to set environment variables and clean up after test
func withEnv(t *testing.T, env map[string]string, fn func()) {
	t.Helper()

	// Save original values and set new ones
	original := make(map[string]string)
	for k, v := range env {
		if orig, exists := os.LookupEnv(k); exists {
			original[k] = orig
		}
		os.Setenv(k, v)
	}

	// Run the test function
	fn()

	// Restore original values
	for k := range env {
		if orig, exists := original[k]; exists {
			os.Setenv(k, orig)
		} else {
			os.Unsetenv(k)
		}
	}
}

// Helper to clear all CI platform env vars
func clearCIPlatformEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD",
		"CIRCLECI", "JENKINS_URL", "BITBUCKET_BUILD_NUMBER",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}
}

func TestDetectPlatform_GitHubActions(t *testing.T) {
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{"GITHUB_ACTIONS": "true"}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformGitHubActions, platform)
	})
}

func TestDetectPlatform_GitLabCI(t *testing.T) {
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{"GITLAB_CI": "true"}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformGitLabCI, platform)
	})
}

func TestDetectPlatform_AzureDevOps(t *testing.T) {
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{"TF_BUILD": "True"}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformAzureDevOps, platform)
	})
}

func TestDetectPlatform_CircleCI(t *testing.T) {
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{"CIRCLECI": "true"}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformCircleCI, platform)
	})
}

func TestDetectPlatform_Jenkins(t *testing.T) {
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{"JENKINS_URL": "http://jenkins.example.com"}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformJenkins, platform)
	})
}

func TestDetectPlatform_Bitbucket(t *testing.T) {
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{"BITBUCKET_BUILD_NUMBER": "42"}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformBitbucket, platform)
	})
}

func TestDetectPlatform_Unknown(t *testing.T) {
	clearCIPlatformEnv(t)
	platform := detectPlatform()
	assert.Equal(t, models.PlatformUnknown, platform)
}

func TestDetectPlatform_Priority(t *testing.T) {
	// When multiple CI env vars are set, GitHub Actions should take priority
	clearCIPlatformEnv(t)
	withEnv(t, map[string]string{
		"GITHUB_ACTIONS": "true",
		"GITLAB_CI":      "true",
	}, func() {
		platform := detectPlatform()
		assert.Equal(t, models.PlatformGitHubActions, platform)
	})
}

func TestContainsSecretKeyword(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"contains SECRET", "AWS_SECRET_ACCESS_KEY", true},
		{"contains PASSWORD", "DATABASE_PASSWORD", true},
		{"contains TOKEN", "GITHUB_TOKEN", true},
		{"contains KEY", "API_KEY", true},
		{"contains CREDENTIAL", "AZURE_CREDENTIAL", true},
		{"contains API_KEY", "MY_API_KEY", true},
		{"contains APIKEY", "MYAPIKEY", true},
		{"contains AUTH", "AUTH_TOKEN", true},
		{"contains PRIVATE", "SSH_PRIVATE_KEY", true},
		{"contains CERT", "SSL_CERT", true},
		{"no keyword", "HOSTNAME", false},
		{"no keyword DATABASE_URL", "DATABASE_URL", false},
		{"empty string", "", false},
		{"partial match not enough", "TOKENSTUFF", true}, // TOKEN is in it
		{"lowercase not matched", "secret_key", false},   // We check uppercase only
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSecretKeyword(tt.input)
			assert.Equal(t, tt.expected, result, "input: %s", tt.input)
		})
	}
}

func TestClassifySecretByName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected models.SecretType
	}{
		// AWS
		{"AWS prefix", "AWS_ACCESS_KEY_ID", models.SecretTypeAWS},
		{"AWS secret", "AWS_SECRET_ACCESS_KEY", models.SecretTypeAWS},

		// GCP
		{"GCP prefix", "GCP_SERVICE_ACCOUNT", models.SecretTypeGCP},
		{"GOOGLE prefix", "GOOGLE_APPLICATION_CREDENTIALS", models.SecretTypeGCP},

		// Azure
		{"AZURE prefix", "AZURE_CLIENT_SECRET", models.SecretTypeAzure},
		{"ARM prefix", "ARM_CLIENT_SECRET", models.SecretTypeAzure},

		// GitHub
		{"GITHUB prefix", "GITHUB_TOKEN", models.SecretTypeGitHub},
		{"GH_ prefix", "GH_TOKEN", models.SecretTypeGitHub},

		// NPM
		{"NPM prefix", "NPM_TOKEN", models.SecretTypeNPM},
		{"NODE prefix", "NODE_AUTH_TOKEN", models.SecretTypeNPM},

		// Docker
		{"DOCKER prefix", "DOCKER_PASSWORD", models.SecretTypeDocker},

		// SSH
		{"SSH prefix", "SSH_PRIVATE_KEY", models.SecretTypeSSH},
		{"DEPLOY prefix", "DEPLOY_KEY", models.SecretTypeSSH},

		// Database
		{"DATABASE prefix", "DATABASE_PASSWORD", models.SecretTypeDatabase},
		{"DB_ prefix", "DB_PASSWORD", models.SecretTypeDatabase},
		{"POSTGRES prefix", "POSTGRES_PASSWORD", models.SecretTypeDatabase},
		{"MYSQL prefix", "MYSQL_PASSWORD", models.SecretTypeDatabase},

		// Generic fallback
		{"unknown secret", "RANDOM_SECRET_KEY", models.SecretTypeGeneric},
		{"API key", "STRIPE_API_KEY", models.SecretTypeGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySecretByName(tt.input)
			assert.Equal(t, tt.expected, result, "input: %s", tt.input)
		})
	}
}

func TestRedactToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty token", "", ""},
		{"short token 4 chars", "abcd", "•••"},
		{"short token 8 chars", "abcdefgh", "•••"},
		{"normal token", "ghp_1234567890abcdefghij", "ghp_•••ghij"},
		{"long token", "ghs_verylongtokenwithlotsofrandomcharacters", "ghs_•••ters"},
		{"9 char token", "123456789", "1234•••6789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactToken(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsRunningInContainer_NotInContainer(t *testing.T) {
	// In most test environments, we're not in a container
	// This test documents the expected behavior
	result := isRunningInContainer()
	// We can't assert true or false definitively without knowing the test env
	// Just verify it returns a boolean without panicking
	assert.IsType(t, true, result)
}

func TestAgent_Recon_BasicExecution(t *testing.T) {
	// Clear CI env to ensure predictable results
	clearCIPlatformEnv(t)

	agent := New(DefaultConfig())
	result := agent.Recon()

	// Basic checks that should always pass
	assert.NotEmpty(t, result.AgentID)
	assert.False(t, result.Timestamp.IsZero())
	assert.Equal(t, models.PlatformUnknown, result.Platform)
	assert.NotNil(t, result.Runner)
	assert.NotNil(t, result.Network)
	assert.NotNil(t, result.Secrets)
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestAgent_Recon_GitHubActions(t *testing.T) {
	clearCIPlatformEnv(t)

	env := map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "acme/api",
		"GITHUB_WORKFLOW":   "CI",
		"GITHUB_JOB":        "build",
		"GITHUB_ACTOR":      "developer",
		"GITHUB_EVENT_NAME": "push",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "abc123",
	}

	withEnv(t, env, func() {
		agent := New(DefaultConfig())
		result := agent.Recon()

		assert.Equal(t, models.PlatformGitHubActions, result.Platform)

		// Repository info
		assert.NotNil(t, result.Repository)
		assert.Equal(t, "acme/api", result.Repository.FullName)
		assert.Equal(t, "acme", result.Repository.Owner)
		assert.Equal(t, "api", result.Repository.Name)

		// Workflow info
		assert.NotNil(t, result.Workflow)
		assert.Equal(t, "CI", result.Workflow.Name)
		assert.Equal(t, "build", result.Workflow.Job)
		assert.Equal(t, "developer", result.Workflow.Actor)
		assert.Equal(t, "push", result.Workflow.Event)
		assert.Equal(t, "refs/heads/main", result.Workflow.Ref)
		assert.Equal(t, "abc123", result.Workflow.SHA)
	})
}

func TestAgent_Recon_GitHubActionsOIDC(t *testing.T) {
	clearCIPlatformEnv(t)

	env := map[string]string{
		"GITHUB_ACTIONS":                 "true",
		"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://token.actions.githubusercontent.com",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret-request-token",
	}

	withEnv(t, env, func() {
		agent := New(DefaultConfig())
		result := agent.Recon()

		assert.NotNil(t, result.OIDC)
		assert.True(t, result.OIDC.Available)
		assert.Equal(t, "https://token.actions.githubusercontent.com", result.OIDC.TokenURL)
		// Token should be redacted
		assert.Contains(t, result.OIDC.RequestToken, "•••")
	})
}

func TestAgent_Recon_SecretDetection(t *testing.T) {
	clearCIPlatformEnv(t)

	env := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"GITHUB_TOKEN":          "ghp_xxxxxxxxxxxxxxxxxxxx",
		"DATABASE_URL":          "postgres://user:pass@localhost/db",
		"NORMAL_VAR":            "nothing-secret-here",
	}

	withEnv(t, env, func() {
		agent := New(DefaultConfig())
		result := agent.Recon()

		// Should detect at least the AWS and GitHub secrets
		assert.GreaterOrEqual(t, len(result.Secrets), 3)

		// Check for specific secrets
		var foundAWSKey, foundGitHubToken bool
		for _, s := range result.Secrets {
			if s.Name == "AWS_ACCESS_KEY_ID" {
				foundAWSKey = true
				assert.Equal(t, models.SecretTypeAWS, s.Type)
				assert.True(t, s.HighValue)
				assert.Equal(t, 20, s.Length)
			}
			if s.Name == "GITHUB_TOKEN" {
				foundGitHubToken = true
				assert.Equal(t, models.SecretTypeGitHub, s.Type)
				assert.True(t, s.HighValue)
			}
		}

		assert.True(t, foundAWSKey, "AWS_ACCESS_KEY_ID should be detected")
		assert.True(t, foundGitHubToken, "GITHUB_TOKEN should be detected")
	})
}

func TestAgent_Recon_RunnerInfo(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Recon()

	assert.NotNil(t, result.Runner)
	assert.NotEmpty(t, result.Runner.OS)
	assert.NotEmpty(t, result.Runner.Arch)
	assert.NotEmpty(t, result.Runner.Hostname)
}

func TestAgent_Recon_NetworkInfo(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Recon()

	assert.NotNil(t, result.Network)
	// Network interfaces should be detected (at least lo or similar)
	// We can't assert specific values as they vary by environment
	assert.IsType(t, []string{}, result.Network.Interfaces)
	assert.IsType(t, true, result.Network.CanReachInternet)
	assert.IsType(t, false, result.Network.ProxyConfigured)
}

func TestAgent_Recon_Duration(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Recon()

	// Duration should be non-negative (may be 0 if recon completes very fast)
	assert.GreaterOrEqual(t, result.Duration, float64(0))
	// And reasonably small (less than 10 seconds for local test)
	assert.Less(t, result.Duration, float64(10000))
}

func TestExtractGitHubPermissions(t *testing.T) {
	// Currently this function looks for GITHUB_*_PERMISSION env vars
	// which are not standard - it's a placeholder for future implementation
	perms := extractGitHubPermissions()
	assert.NotNil(t, perms)
	// Empty map is expected since we don't have permission vars set
	assert.IsType(t, map[string]string{}, perms)
}

func TestGatherRunnerInfo(t *testing.T) {
	agent := New(DefaultConfig())
	info := agent.gatherRunnerInfo()

	assert.NotNil(t, info)
	assert.NotEmpty(t, info.OS)
	assert.NotEmpty(t, info.Arch)
	assert.NotEmpty(t, info.Hostname)
}

func TestGatherRunnerInfo_WithGitHubEnv(t *testing.T) {
	env := map[string]string{
		"RUNNER_NAME":       "ubuntu-latest",
		"GITHUB_WORKSPACE":  "/home/runner/work/repo/repo",
		"RUNNER_TEMP":       "/home/runner/work/_temp",
		"RUNNER_TOOL_CACHE": "/opt/hostedtoolcache",
		"RUNNER_LABELS":     "ubuntu-latest,ubuntu-22.04",
	}

	withEnv(t, env, func() {
		agent := New(DefaultConfig())
		info := agent.gatherRunnerInfo()

		assert.Equal(t, "ubuntu-latest", info.Name)
		assert.Equal(t, "/home/runner/work/repo/repo", info.Workspace)
		assert.Equal(t, "/home/runner/work/_temp", info.TempDir)
		assert.Equal(t, "/opt/hostedtoolcache", info.ToolCache)
		assert.False(t, info.SelfHosted) // "ubuntu-latest" in labels means hosted
	})
}

func TestGatherRunnerInfo_SelfHosted(t *testing.T) {
	env := map[string]string{
		"RUNNER_NAME":   "self-hosted-runner",
		"RUNNER_LABELS": "self-hosted,linux,x64",
	}

	withEnv(t, env, func() {
		agent := New(DefaultConfig())
		info := agent.gatherRunnerInfo()

		assert.Equal(t, "self-hosted-runner", info.Name)
		assert.True(t, info.SelfHosted)
	})
}
