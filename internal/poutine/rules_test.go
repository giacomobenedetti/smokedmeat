// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOffensiveRules_InitialAccessFocus(t *testing.T) {
	// OffensiveRules should be focused on initial access vectors
	assert.NotEmpty(t, OffensiveRules)

	// Core initial access rules
	assert.Contains(t, OffensiveRules, "injection")
	assert.Contains(t, OffensiveRules, "pr_runs_on_self_hosted")
	assert.Contains(t, OffensiveRules, "untrusted_checkout_exec")

	// Should be focused (not too many rules)
	assert.LessOrEqual(t, len(OffensiveRules), 5, "OffensiveRules should be focused on initial access")
}

func TestExtendedRules(t *testing.T) {
	assert.NotEmpty(t, ExtendedRules)
	assert.Contains(t, ExtendedRules, "debug_enabled")
	assert.Contains(t, ExtendedRules, "excessive_permissions")
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"error", "critical"},
		{"warning", "high"},
		{"note", "medium"},
		{"info", "low"},
		{"unknown", "low"},
		{"", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapSeverity(tt.input))
		})
	}
}

func TestExtractExpression(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"legacy format", "uses ${{ github.event.pull_request.title }} in run", "${{ github.event.pull_request.title }}"},
		{"no expression", "no expression here", ""},
		{"incomplete", "${{ incomplete", "${{ incomplete"},
		{"multiple legacy", "multiple ${{ first }} and ${{ second }}", "${{ first }}"},
		{"poutine sources single", "Sources: github.event.issue.body", "${{ github.event.issue.body }}"},
		{"poutine sources multiple", "Sources: github.event.issue.body github.event.issue.title", "${{ github.event.issue.body }}"},
		{"poutine sources empty", "Sources: ", ""},
		{"detected usage make", "Detected usage of `make`", "Detected usage of `make`"},
		{"detected usage action", "Detected usage the GitHub Action `gradle/gradle-build-action`", "Detected usage the GitHub Action `gradle/gradle-build-action`"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractExpression(tt.input))
		})
	}
}

func TestExtractTrigger(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{"single trigger", []string{"pull_request"}, "pull_request"},
		{"multiple triggers", []string{"pull_request", "push"}, "pull_request, push"},
		{"empty", []string{}, "unknown"},
		{"nil", nil, "unknown"},
		{"complex event", []string{"pull_request_target"}, "pull_request_target"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTrigger(tt.input))
		})
	}
}

func TestExtractRepoFromPurl(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"pkg:github/acme/repo", "acme/repo"},
		{"pkg:github/acme/repo@v1.0.0", "acme/repo"},
		{"pkg:github/acme/repo?foo=bar", "acme/repo"},
		{"pkg:github/acme/repo@v1.0.0?foo=bar", "acme/repo"},
		{"pkg:npm/lodash", "pkg:npm/lodash"}, // Non-github purl returned as-is
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractRepoFromPurl(tt.input))
		})
	}
}
