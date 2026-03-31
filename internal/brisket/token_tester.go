// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// TokenTestResult represents the result of token capability testing.
type TokenTestResult struct {
	Success  bool    `json:"success"`
	Duration float64 `json:"duration_ms"`

	// Token metadata
	TokenType   string `json:"token_type"`   // ghp_, ghs_, ghu_, ghat_, github_pat_
	TokenPrefix string `json:"token_prefix"` // First 10 chars (redacted)
	TokenLength int    `json:"token_length"`

	// Identity info (from /user endpoint)
	Login     string `json:"login,omitempty"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"` // User, Bot, App
	ScopesRaw string `json:"scopes_raw,omitempty"`

	// Detected permissions
	Permissions []TokenPermission `json:"permissions"`

	// Accessible resources
	Repos         []RepoAccess `json:"repos,omitempty"`
	Organizations []OrgAccess  `json:"orgs,omitempty"`

	// Rate limit info
	RateLimitRemaining int `json:"rate_limit_remaining"`
	RateLimitReset     int `json:"rate_limit_reset"`

	// Errors encountered during testing
	Errors []string `json:"errors,omitempty"`
}

// TokenPermission represents a tested permission.
type TokenPermission struct {
	Scope       string `json:"scope"` // e.g., "repo", "read:user", "admin:org"
	HasAccess   bool   `json:"has_access"`
	Level       string `json:"level,omitempty"` // read, write, admin
	TestedVia   string `json:"tested_via"`      // API endpoint used to test
	Description string `json:"description,omitempty"`
}

// RepoAccess represents access to a repository.
type RepoAccess struct {
	FullName    string `json:"full_name"`
	Private     bool   `json:"private"`
	Permissions struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
		Pull  bool `json:"pull"`
	} `json:"permissions"`
}

// OrgAccess represents access to an organization.
type OrgAccess struct {
	Login string `json:"login"`
	Role  string `json:"role,omitempty"` // admin, member
}

// TestToken performs comprehensive GitHub token capability testing.
func (a *Agent) TestToken(args []string) *TokenTestResult {
	start := time.Now()
	result := &TokenTestResult{
		Permissions:   []TokenPermission{},
		Repos:         []RepoAccess{},
		Organizations: []OrgAccess{},
		Errors:        []string{},
	}

	// Get token from args or environment
	token := ""
	if len(args) > 0 {
		token = args[0]
	} else {
		// Try common environment variables
		for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"} {
			if t := os.Getenv(env); t != "" {
				token = t
				break
			}
		}
	}

	if token == "" {
		result.Errors = append(result.Errors, "no token provided (pass as argument or set GITHUB_TOKEN)")
		result.Duration = float64(time.Since(start).Milliseconds())
		return result
	}

	// Analyze token type from prefix
	result.TokenLength = len(token)
	result.TokenPrefix = redactToken(token)
	result.TokenType = detectTokenType(token)

	// Create HTTP client
	client := &http.Client{Timeout: 10 * time.Second}

	// Test identity (always works if token is valid)
	a.testIdentity(client, token, result)

	// Test various permission scopes
	a.testRepoAccess(client, token, result)
	a.testUserPermissions(client, token, result)
	a.testOrgPermissions(client, token, result)
	a.testGistPermissions(client, token, result)
	a.testWorkflowPermissions(client, token, result)
	a.testPackagePermissions(client, token, result)

	// List accessible repos (limited to first 30)
	a.listAccessibleRepos(client, token, result)

	// List organizations
	a.listOrganizations(client, token, result)

	result.Success = len(result.Errors) == 0 || result.Login != ""
	result.Duration = float64(time.Since(start).Milliseconds())
	return result
}

// detectTokenType identifies the GitHub token type from its prefix.
func detectTokenType(token string) string {
	prefixes := map[string]string{
		"ghp_":        "Personal Access Token (Classic)",
		"github_pat_": "Personal Access Token (Fine-Grained)",
		"ghs_":        "GitHub Actions Token",
		"ghu_":        "User-to-Server Token (OAuth)",
		"gho_":        "OAuth Access Token",
		"ghr_":        "Refresh Token",
		"ghat_":       "GitHub App Token",
	}

	for prefix, tokenType := range prefixes {
		if strings.HasPrefix(token, prefix) {
			return tokenType
		}
	}

	// Check for legacy tokens (40 char hex)
	if len(token) == 40 && isHex(token) {
		return "Personal Access Token (Legacy)"
	}

	return "Unknown"
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// testIdentity tests basic token validity and gets user info.
func (a *Agent) testIdentity(client *http.Client, token string, result *TokenTestResult) {
	resp, body, err := a.githubAPI(client, token, "GET", "/user", nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("identity test failed: %v", err))
		return
	}

	// Check rate limit headers
	if resp != nil {
		if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
			_, _ = fmt.Sscanf(remaining, "%d", &result.RateLimitRemaining)
		}
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			_, _ = fmt.Sscanf(reset, "%d", &result.RateLimitReset)
		}
		// Classic PATs return scopes in header
		if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {
			result.ScopesRaw = scopes
		}
	}

	if resp.StatusCode == http.StatusOK {
		var user struct {
			Login string `json:"login"`
			Name  string `json:"name"`
			Type  string `json:"type"`
		}
		if err := json.Unmarshal(body, &user); err == nil {
			result.Login = user.Login
			result.Name = user.Name
			result.Type = user.Type
		}
	}
}

// testRepoAccess tests repository-related permissions.
func (a *Agent) testRepoAccess(client *http.Client, token string, result *TokenTestResult) {
	// Test read access to repos
	resp, _, _ := a.githubAPI(client, token, "GET", "/user/repos?per_page=1", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "repo",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/repos",
		Description: "Access to private repositories",
	})

	// Test if we can access a specific repo's contents (requires repo or public_repo)
	// We'll test with the user's first repo if available
}

// testUserPermissions tests user-related permissions.
func (a *Agent) testUserPermissions(client *http.Client, token string, result *TokenTestResult) {
	// read:user - access to user profile
	resp, _, _ := a.githubAPI(client, token, "GET", "/user", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "read:user",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user",
		Description: "Read access to user profile",
	})

	// user:email - access to email addresses
	resp, _, _ = a.githubAPI(client, token, "GET", "/user/emails", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "user:email",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/emails",
		Description: "Access to email addresses",
	})

	// read:user - access to followers
	resp, _, _ = a.githubAPI(client, token, "GET", "/user/followers?per_page=1", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "user:follow",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/followers",
		Description: "Access to followers list",
	})

	// read:ssh_signing_key
	resp, _, _ = a.githubAPI(client, token, "GET", "/user/ssh_signing_keys", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "read:ssh_signing_key",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/ssh_signing_keys",
		Description: "Access to SSH signing keys",
	})

	// read:gpg_key
	resp, _, _ = a.githubAPI(client, token, "GET", "/user/gpg_keys", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "read:gpg_key",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/gpg_keys",
		Description: "Access to GPG keys",
	})
}

// testOrgPermissions tests organization-related permissions.
func (a *Agent) testOrgPermissions(client *http.Client, token string, result *TokenTestResult) {
	// read:org - access to organizations
	resp, _, _ := a.githubAPI(client, token, "GET", "/user/orgs", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "read:org",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/orgs",
		Description: "Read access to organizations",
	})

	// admin:org - need an org to test, skip for now
}

// testGistPermissions tests gist-related permissions.
func (a *Agent) testGistPermissions(client *http.Client, token string, result *TokenTestResult) {
	resp, _, _ := a.githubAPI(client, token, "GET", "/gists", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "gist",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /gists",
		Description: "Access to gists",
	})
}

// testWorkflowPermissions tests GitHub Actions workflow permissions.
func (a *Agent) testWorkflowPermissions(client *http.Client, token string, result *TokenTestResult) {
	// We need a repo to test this properly
	// For now, we check if the token is a GitHub Actions token
	if strings.HasPrefix(result.TokenType, "GitHub Actions") {
		result.Permissions = append(result.Permissions, TokenPermission{
			Scope:       "actions",
			HasAccess:   true,
			Level:       "write",
			TestedVia:   "Token prefix analysis",
			Description: "GitHub Actions workflow token",
		})
	}
}

// testPackagePermissions tests package-related permissions.
func (a *Agent) testPackagePermissions(client *http.Client, token string, result *TokenTestResult) {
	resp, _, _ := a.githubAPI(client, token, "GET", "/user/packages?package_type=container", nil)
	result.Permissions = append(result.Permissions, TokenPermission{
		Scope:       "read:packages",
		HasAccess:   resp != nil && resp.StatusCode == http.StatusOK,
		Level:       "read",
		TestedVia:   "GET /user/packages",
		Description: "Access to packages",
	})
}

// listAccessibleRepos lists repositories the token can access.
func (a *Agent) listAccessibleRepos(client *http.Client, token string, result *TokenTestResult) {
	resp, body, err := a.githubAPI(client, token, "GET", "/user/repos?per_page=30&sort=updated", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}

	var repos []struct {
		FullName    string `json:"full_name"`
		Private     bool   `json:"private"`
		Permissions struct {
			Admin bool `json:"admin"`
			Push  bool `json:"push"`
			Pull  bool `json:"pull"`
		} `json:"permissions"`
	}

	if err := json.Unmarshal(body, &repos); err != nil {
		return
	}

	for _, repo := range repos {
		result.Repos = append(result.Repos, RepoAccess{
			FullName: repo.FullName,
			Private:  repo.Private,
			Permissions: struct {
				Admin bool `json:"admin"`
				Push  bool `json:"push"`
				Pull  bool `json:"pull"`
			}{
				Admin: repo.Permissions.Admin,
				Push:  repo.Permissions.Push,
				Pull:  repo.Permissions.Pull,
			},
		})
	}
}

// listOrganizations lists organizations the token has access to.
func (a *Agent) listOrganizations(client *http.Client, token string, result *TokenTestResult) {
	resp, body, err := a.githubAPI(client, token, "GET", "/user/orgs", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}

	var orgs []struct {
		Login string `json:"login"`
	}

	if err := json.Unmarshal(body, &orgs); err != nil {
		return
	}

	for _, org := range orgs {
		result.Organizations = append(result.Organizations, OrgAccess{
			Login: org.Login,
		})
	}
}

// githubAPI makes a request to the GitHub API.
func (a *Agent) githubAPI(client *http.Client, token, method, path string, body []byte) (*http.Response, []byte, error) {
	url := "https://api.github.com" + path

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "SmokedMeat-TokenTester")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return resp, respBody, nil
}

// MarshalTokenTestResult serializes a TokenTestResult to JSON.
func (r *TokenTestResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
