// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectTokenType(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		// Classic Personal Access Token
		{"ghp token", "ghp_1234567890abcdef", "Personal Access Token (Classic)"},
		{"empty ghp", "ghp_", "Personal Access Token (Classic)"},

		// GitHub Actions tokens
		{"ghs token", "ghs_abcdefgh12345678", "GitHub Actions Token"},

		// User-to-server tokens (OAuth)
		{"ghu token", "ghu_xyz123456789", "User-to-Server Token (OAuth)"},

		// GitHub App tokens
		{"ghat token", "ghat_abcd1234", "GitHub App Token"},

		// Fine-grained PAT
		{"github_pat token", "github_pat_xyz123", "Personal Access Token (Fine-Grained)"},

		// Refresh tokens
		{"ghr token", "ghr_refresh123", "Refresh Token"},

		// OAuth tokens
		{"gho token", "gho_oauth123", "OAuth Access Token"},

		// Legacy token (40 hex chars)
		{"legacy hex token", "0123456789abcdef0123456789abcdef01234567", "Personal Access Token (Legacy)"},

		// Unknown format
		{"unknown format", "randomtoken123", "Unknown"},
		{"empty token", "", "Unknown"},
		{"short token", "gh", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectTokenType(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"0123456789abcdef", true},
		{"ABCDEF", true},
		{"abcdef", true},
		{"0123456789ABCDEF0123456789abcdef01234567", true},
		{"ghxyz", false},
		{"hello!", false},
		{"", true}, // empty string is technically valid hex
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isHex(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTestToken_NoToken(t *testing.T) {
	// Save and clear environment
	savedToken := os.Getenv("GITHUB_TOKEN")
	savedGHToken := os.Getenv("GH_TOKEN")
	savedPAT := os.Getenv("GITHUB_PAT")
	os.Unsetenv("GITHUB_TOKEN")
	os.Unsetenv("GH_TOKEN")
	os.Unsetenv("GITHUB_PAT")
	defer func() {
		if savedToken != "" {
			os.Setenv("GITHUB_TOKEN", savedToken)
		}
		if savedGHToken != "" {
			os.Setenv("GH_TOKEN", savedGHToken)
		}
		if savedPAT != "" {
			os.Setenv("GITHUB_PAT", savedPAT)
		}
	}()

	agent := New(DefaultConfig())
	result := agent.TestToken(nil)

	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "no token provided")
}

func TestTestToken_WithExplicitToken(t *testing.T) {
	agent := New(DefaultConfig())

	// Using a clearly invalid token to test the token type detection
	// Real API calls will fail, but token detection should work
	result := agent.TestToken([]string{"ghp_testtoken123456789"})

	// Token type should be detected
	assert.Equal(t, "Personal Access Token (Classic)", result.TokenType)
	// Duration should be recorded
	assert.GreaterOrEqual(t, result.Duration, float64(0))
	// Token length should be recorded
	assert.Equal(t, 22, result.TokenLength)
}

func TestTestToken_DetectsTokenTypes(t *testing.T) {
	agent := New(DefaultConfig())

	tests := []struct {
		token        string
		expectedType string
	}{
		{"ghp_test123", "Personal Access Token (Classic)"},
		{"ghs_test123", "GitHub Actions Token"},
		{"ghu_test123", "User-to-Server Token (OAuth)"},
		{"ghat_test123", "GitHub App Token"},
		{"github_pat_test123", "Personal Access Token (Fine-Grained)"},
		{"gho_test123", "OAuth Access Token"},
		{"ghr_test123", "Refresh Token"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedType, func(t *testing.T) {
			result := agent.TestToken([]string{tt.token})
			assert.Equal(t, tt.expectedType, result.TokenType)
		})
	}
}

func TestTestToken_FromEnvironment(t *testing.T) {
	// Test that token is read from environment
	withEnv(t, map[string]string{
		"GITHUB_TOKEN": "ghp_envtoken123",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.TestToken(nil)

		// Should use the env token and detect its type
		assert.Equal(t, "Personal Access Token (Classic)", result.TokenType)
	})
}

func TestTestToken_GHTokenFallback(t *testing.T) {
	// Clear GITHUB_TOKEN, set GH_TOKEN
	savedToken := os.Getenv("GITHUB_TOKEN")
	savedPAT := os.Getenv("GITHUB_PAT")
	os.Unsetenv("GITHUB_TOKEN")
	os.Unsetenv("GITHUB_PAT")
	defer func() {
		if savedToken != "" {
			os.Setenv("GITHUB_TOKEN", savedToken)
		}
		if savedPAT != "" {
			os.Setenv("GITHUB_PAT", savedPAT)
		}
	}()

	withEnv(t, map[string]string{
		"GH_TOKEN": "ghs_fallbacktoken",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.TestToken(nil)

		assert.Equal(t, "GitHub Actions Token", result.TokenType)
	})
}

func TestTokenTestResult_Marshal(t *testing.T) {
	result := &TokenTestResult{
		Success:   true,
		TokenType: "Personal Access Token (Classic)",
		Login:     "testuser",
		Permissions: []TokenPermission{
			{Scope: "repo", HasAccess: true, Level: "read"},
		},
	}

	data, err := result.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), `"success":true`)
	assert.Contains(t, string(data), `"token_type":"Personal Access Token (Classic)"`)
	assert.Contains(t, string(data), `"login":"testuser"`)
	assert.Contains(t, string(data), `"scope":"repo"`)
}

func TestTokenPermission_Structure(t *testing.T) {
	perm := TokenPermission{
		Scope:       "repo",
		HasAccess:   true,
		Level:       "write",
		TestedVia:   "GET /user/repos",
		Description: "Full control of private repositories",
	}

	assert.Equal(t, "repo", perm.Scope)
	assert.True(t, perm.HasAccess)
	assert.Equal(t, "write", perm.Level)
	assert.Equal(t, "GET /user/repos", perm.TestedVia)
	assert.Equal(t, "Full control of private repositories", perm.Description)
}

func TestRepoAccess_Structure(t *testing.T) {
	repo := RepoAccess{
		FullName: "owner/test-repo",
		Private:  true,
		Permissions: struct {
			Admin bool `json:"admin"`
			Push  bool `json:"push"`
			Pull  bool `json:"pull"`
		}{
			Admin: true,
			Push:  true,
			Pull:  true,
		},
	}

	assert.Equal(t, "owner/test-repo", repo.FullName)
	assert.True(t, repo.Private)
	assert.True(t, repo.Permissions.Admin)
	assert.True(t, repo.Permissions.Push)
	assert.True(t, repo.Permissions.Pull)
}

func TestOrgAccess_Structure(t *testing.T) {
	org := OrgAccess{
		Login: "test-org",
		Role:  "admin",
	}

	assert.Equal(t, "test-org", org.Login)
	assert.Equal(t, "admin", org.Role)
}

func TestTokenTestResult_Duration(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.TestToken([]string{"ghp_test"})

	// Duration should be non-negative
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestTokenTestResult_ErrorsSlice(t *testing.T) {
	result := &TokenTestResult{
		Errors: []string{"error1", "error2"},
	}

	assert.Len(t, result.Errors, 2)
	assert.Equal(t, "error1", result.Errors[0])
	assert.Equal(t, "error2", result.Errors[1])
}

func TestTokenTestResult_TokenPrefix(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.TestToken([]string{"ghp_verylongtokenvalue123456"})

	// Token prefix should be redacted
	assert.NotEmpty(t, result.TokenPrefix)
	assert.Contains(t, result.TokenPrefix, "•••")
}
