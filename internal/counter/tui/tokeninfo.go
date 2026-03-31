// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"
	"time"
)

// TokenType represents the type of GitHub token
type TokenType string

const (
	TokenTypeClassicPAT     TokenType = "classic_pat"
	TokenTypeFineGrainedPAT TokenType = "fine_grained_pat"
	TokenTypeOAuth          TokenType = "oauth"
	TokenTypeUserApp        TokenType = "user_app"
	TokenTypeInstallApp     TokenType = "install_app"
	TokenTypeGitHubActions  TokenType = "actions"
	TokenTypeUnknown        TokenType = "unknown"
)

// TokenInfo holds token metadata including type, source, and capabilities
type TokenInfo struct {
	Value        string
	Type         TokenType
	Source       string // op, gh, input, loot
	Scopes       []string
	Owner        string // username or app name
	RateLimitMax int
	ExpiresAt    *time.Time
	FetchedAt    time.Time
}

// DetectTokenType determines the token type from its prefix
func DetectTokenType(token string) TokenType {
	switch {
	case strings.HasPrefix(token, "ghp_"):
		return TokenTypeClassicPAT
	case strings.HasPrefix(token, "github_pat_"):
		return TokenTypeFineGrainedPAT
	case strings.HasPrefix(token, "gho_"):
		return TokenTypeOAuth
	case strings.HasPrefix(token, "ghu_"):
		return TokenTypeUserApp
	case strings.HasPrefix(token, "ghs_"):
		return TokenTypeInstallApp
	default:
		return TokenTypeUnknown
	}
}

// ShortType returns a short display string for the token type
func (t TokenType) ShortType() string {
	switch t {
	case TokenTypeClassicPAT:
		return "PAT"
	case TokenTypeFineGrainedPAT:
		return "FG-PAT"
	case TokenTypeOAuth:
		return "OAuth"
	case TokenTypeUserApp:
		return "App-User"
	case TokenTypeInstallApp:
		return "App-Install"
	case TokenTypeGitHubActions:
		return "Actions"
	default:
		return "token"
	}
}

// FullTypeName returns a human-readable token type name
func (t TokenType) FullTypeName() string {
	switch t {
	case TokenTypeClassicPAT:
		return "Classic PAT"
	case TokenTypeFineGrainedPAT:
		return "Fine-grained PAT"
	case TokenTypeOAuth:
		return "OAuth Token"
	case TokenTypeUserApp:
		return "GitHub App (User)"
	case TokenTypeInstallApp:
		return "GitHub App (Install)"
	case TokenTypeGitHubActions:
		return "Actions Token"
	default:
		return "Token"
	}
}

// FullSourceName returns a human-readable source name
func FullSourceName(source string) string {
	switch source {
	case "op":
		return "1Password"
	case "gh":
		return "GitHub CLI"
	case "input":
		return "manual input"
	case "loot":
		return "loot"
	case "config":
		return "saved config"
	default:
		return source
	}
}

// MaskedValue returns the token with middle chars hidden
func (t *TokenInfo) MaskedValue() string {
	if len(t.Value) < 8 {
		return "***"
	}
	return t.Value[:4] + "…" + t.Value[len(t.Value)-4:]
}

// DisplaySource returns a formatted source string for status bar
func (t *TokenInfo) DisplaySource() string {
	typeStr := t.Type.ShortType()
	if t.Source == "" {
		return typeStr
	}
	return typeStr + "/" + t.Source
}

// ScopeSummary returns a brief summary of scopes
func (t *TokenInfo) ScopeSummary() string {
	if len(t.Scopes) == 0 {
		return "no scopes"
	}
	if len(t.Scopes) <= 3 {
		return strings.Join(t.Scopes, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(t.Scopes[:2], ", "), len(t.Scopes)-2)
}

// HasScope checks if the token has a specific scope
func (t *TokenInfo) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// CanUseDelivery checks if token has required scopes for a delivery method.
// Returns true if the method should be enabled, false if it should be disabled/warned.
func (t *TokenInfo) CanUseDelivery(method DeliveryMethod) bool {
	if t == nil {
		return method == DeliveryCopyOnly || method == DeliveryManualSteps
	}

	switch method {
	case DeliveryAutoPR, DeliveryLOTP:
		return t.HasScope("repo") || t.HasScope("public_repo") ||
			t.Type == TokenTypeFineGrainedPAT
	case DeliveryIssue, DeliveryComment:
		return t.HasScope("repo") || t.HasScope("public_repo") ||
			t.Type == TokenTypeFineGrainedPAT
	case DeliveryAutoDispatch:
		return false // Requires ephemeral token from loot, not operator PAT
	case DeliveryCopyOnly, DeliveryManualSteps:
		return true
	}
	return false
}
