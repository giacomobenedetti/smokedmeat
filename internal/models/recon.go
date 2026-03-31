// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package models contains domain models for SmokedMeat.
package models

import (
	"encoding/json"
	"time"
)

// CIPlatform identifies the CI/CD platform.
type CIPlatform string

const (
	PlatformUnknown       CIPlatform = "unknown"
	PlatformGitHubActions CIPlatform = "github_actions"
	PlatformGitLabCI      CIPlatform = "gitlab_ci"
	PlatformAzureDevOps   CIPlatform = "azure_devops"
	PlatformCircleCI      CIPlatform = "circleci"
	PlatformJenkins       CIPlatform = "jenkins"
	PlatformBitbucket     CIPlatform = "bitbucket"
)

// SecretType classifies detected secrets.
type SecretType string

const (
	SecretTypeGeneric  SecretType = "generic"
	SecretTypeAWS      SecretType = "aws"
	SecretTypeGCP      SecretType = "gcp"
	SecretTypeAzure    SecretType = "azure"
	SecretTypeGitHub   SecretType = "github"
	SecretTypeNPM      SecretType = "npm"
	SecretTypeDocker   SecretType = "docker"
	SecretTypeSSH      SecretType = "ssh"
	SecretTypeDatabase SecretType = "database"
	SecretTypeAPI      SecretType = "api"
	SecretTypeOIDC     SecretType = "oidc"
)

// DetectedSecret represents a secret found in the environment.
type DetectedSecret struct {
	Name      string     `json:"name"`
	Type      SecretType `json:"type"`
	Length    int        `json:"length"`
	Prefix    string     `json:"prefix,omitempty"` // First few chars for identification
	Source    string     `json:"source,omitempty"` // Where it came from (env, file, etc.)
	HighValue bool       `json:"high_value"`       // Likely to grant significant access
}

// RepoInfo contains information about a discovered repository.
type RepoInfo struct {
	FullName      string            `json:"full_name"` // org/repo
	Owner         string            `json:"owner"`
	Name          string            `json:"name"`
	Platform      CIPlatform        `json:"platform"`
	Permissions   map[string]string `json:"permissions,omitempty"`
	DefaultBranch string            `json:"default_branch,omitempty"`
}

// WorkflowInfo contains information about the current workflow.
type WorkflowInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	RunID     string `json:"run_id,omitempty"`
	RunNumber string `json:"run_number,omitempty"`
	Job       string `json:"job,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Event     string `json:"event,omitempty"` // push, pull_request, workflow_dispatch, etc.
	Ref       string `json:"ref,omitempty"`   // refs/heads/main, refs/pull/123/merge
	SHA       string `json:"sha,omitempty"`
}

// OIDCInfo contains OIDC token availability information.
type OIDCInfo struct {
	Available    bool              `json:"available"`
	TokenURL     string            `json:"token_url,omitempty"`
	RequestURL   string            `json:"request_url,omitempty"`
	RequestToken string            `json:"request_token,omitempty"` // Redacted
	Claims       map[string]string `json:"claims,omitempty"`        // Decoded claims if available
}

// RunnerInfo contains information about the runner environment.
type RunnerInfo struct {
	Name       string `json:"name,omitempty"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Hostname   string `json:"hostname"`
	SelfHosted bool   `json:"self_hosted"`
	Container  bool   `json:"container"`
	ToolCache  string `json:"tool_cache,omitempty"`
	Workspace  string `json:"workspace,omitempty"`
	TempDir    string `json:"temp_dir,omitempty"`
}

// NetworkInfo contains network-related information.
type NetworkInfo struct {
	Interfaces       []string `json:"interfaces,omitempty"`
	CanReachInternet bool     `json:"can_reach_internet"`
	ProxyConfigured  bool     `json:"proxy_configured"`
}

// ReconResult is the complete reconnaissance output from a Brisket agent.
type ReconResult struct {
	// Metadata
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Duration  float64   `json:"duration_ms"`

	// Platform identification
	Platform CIPlatform `json:"platform"`

	// Repository context
	Repository *RepoInfo `json:"repository,omitempty"`

	// Workflow context
	Workflow *WorkflowInfo `json:"workflow,omitempty"`

	// Runner environment
	Runner *RunnerInfo `json:"runner,omitempty"`

	// Discovered secrets
	Secrets []DetectedSecret `json:"secrets"`

	// OIDC availability
	OIDC *OIDCInfo `json:"oidc,omitempty"`

	// Network information
	Network *NetworkInfo `json:"network,omitempty"`

	// GitHub-specific permissions (from GITHUB_TOKEN)
	TokenPermissions map[string]string `json:"token_permissions,omitempty"`

	// Raw environment variables (filtered)
	Environment map[string]string `json:"environment,omitempty"`

	// Errors encountered during recon
	Errors []string `json:"errors,omitempty"`
}

// NewReconResult creates a new ReconResult with defaults.
func NewReconResult(agentID string) *ReconResult {
	return &ReconResult{
		AgentID:   agentID,
		Timestamp: time.Now().UTC(),
		Platform:  PlatformUnknown,
		Secrets:   []DetectedSecret{},
		Errors:    []string{},
	}
}

// Marshal serializes the ReconResult to JSON.
func (r *ReconResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// UnmarshalReconResult deserializes a ReconResult from JSON.
func UnmarshalReconResult(data []byte) (*ReconResult, error) {
	var r ReconResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// AddSecret adds a detected secret to the result.
func (r *ReconResult) AddSecret(name string, secretType SecretType, length int, highValue bool) {
	r.Secrets = append(r.Secrets, DetectedSecret{
		Name:      name,
		Type:      secretType,
		Length:    length,
		HighValue: highValue,
		Source:    "environment",
	})
}

// AddError records an error encountered during recon.
func (r *ReconResult) AddError(err string) {
	r.Errors = append(r.Errors, err)
}

// HasHighValueSecrets returns true if any high-value secrets were found.
func (r *ReconResult) HasHighValueSecrets() bool {
	for _, s := range r.Secrets {
		if s.HighValue {
			return true
		}
	}
	return false
}

// SecretCount returns the number of secrets detected.
func (r *ReconResult) SecretCount() int {
	return len(r.Secrets)
}

// HighValueSecretCount returns the number of high-value secrets.
func (r *ReconResult) HighValueSecretCount() int {
	count := 0
	for _, s := range r.Secrets {
		if s.HighValue {
			count++
		}
	}
	return count
}
