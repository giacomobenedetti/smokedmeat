// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func TestScan_NonexistentPath(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Scan([]string{"/nonexistent/path/that/does/not/exist"})

	// Scan should fail but not panic
	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Errors)
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestScan_CurrentDirectory(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Scan(nil)

	// Scan of current directory (the smokedmeat repo itself)
	// May or may not find findings, but should complete
	assert.NotEmpty(t, result.Path)
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestScan_EmptyArgs(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Scan([]string{})

	// Should default to current directory
	assert.NotEmpty(t, result.Path)
}

func TestScanResult_Marshal(t *testing.T) {
	result := &models.ScanResult{
		Success:       true,
		Path:          "/test/path",
		Repository:    "owner/repo",
		TotalFindings: 2,
		Findings: []models.ScanFinding{
			{RuleID: "injection", Title: "Injection vulnerability", Severity: "error"},
		},
		Rules: map[string]models.ScanRule{
			"injection": {ID: "injection", Title: "Injection vulnerability", Severity: "error"},
		},
	}

	data, err := result.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), `"success":true`)
	assert.Contains(t, string(data), `"path":"/test/path"`)
	assert.Contains(t, string(data), `"repository":"owner/repo"`)
	assert.Contains(t, string(data), `"rule_id":"injection"`)
}

func TestScanFinding_Structure(t *testing.T) {
	finding := models.ScanFinding{
		RuleID:      "injection",
		Title:       "Command Injection",
		Description: "User input flows into command execution",
		Severity:    "error",
		Path:        ".github/workflows/ci.yml",
		Line:        42,
		Job:         "build",
		Step:        "3",
		Fingerprint: "abc123",
	}

	assert.Equal(t, "injection", finding.RuleID)
	assert.Equal(t, "Command Injection", finding.Title)
	assert.Equal(t, "User input flows into command execution", finding.Description)
	assert.Equal(t, "error", finding.Severity)
	assert.Equal(t, ".github/workflows/ci.yml", finding.Path)
	assert.Equal(t, 42, finding.Line)
	assert.Equal(t, "build", finding.Job)
	assert.Equal(t, "3", finding.Step)
	assert.Equal(t, "abc123", finding.Fingerprint)
}

func TestScanRule_Structure(t *testing.T) {
	rule := models.ScanRule{
		ID:          "injection",
		Title:       "Command Injection",
		Description: "Detects command injection vulnerabilities",
		Severity:    "error",
		References:  []string{"https://example.com/ref1"},
	}

	assert.Equal(t, "injection", rule.ID)
	assert.Equal(t, "Command Injection", rule.Title)
	assert.Equal(t, "Detects command injection vulnerabilities", rule.Description)
	assert.Equal(t, "error", rule.Severity)
	assert.Len(t, rule.References, 1)
	assert.Equal(t, "https://example.com/ref1", rule.References[0])
}

func TestOffensiveRules_InitialAccessFocus(t *testing.T) {
	// Now using the shared poutine.OffensiveRules
	assert.NotEmpty(t, poutine.OffensiveRules)
	// Core initial access vectors
	assert.Contains(t, poutine.OffensiveRules, "injection")
	assert.Contains(t, poutine.OffensiveRules, "pr_runs_on_self_hosted")
	assert.Contains(t, poutine.OffensiveRules, "untrusted_checkout_exec")
	// Should be focused - not a laundry list
	assert.LessOrEqual(t, len(poutine.OffensiveRules), 4, "OffensiveRules should be focused on initial access only")
}

func TestScanResult_FormatOutput(t *testing.T) {
	result := &models.ScanResult{
		Success:          true,
		Path:             "/test/path",
		Repository:       "owner/repo",
		TotalFindings:    1,
		CriticalFindings: 1,
		Duration:         123.45,
		Findings: []models.ScanFinding{
			{
				RuleID:   "injection",
				Title:    "Injection",
				Severity: "error",
				Path:     "ci.yml",
				Line:     10,
				Job:      "build",
			},
		},
	}

	output := result.FormatOutput()
	assert.Contains(t, output, "Poutine Scan: /test/path")
	assert.Contains(t, output, "Repository: owner/repo")
	assert.Contains(t, output, "Total findings: 1")
	assert.Contains(t, output, "Critical: 1")
	assert.Contains(t, output, "[error] Injection")
	assert.Contains(t, output, "Path: ci.yml:10")
	assert.Contains(t, output, "Job: build")
}

func TestScanResult_FormatOutput_Failed(t *testing.T) {
	result := &models.ScanResult{
		Success: false,
		Path:    "/test/path",
		Errors:  []string{"scan failed: some error"},
	}

	output := result.FormatOutput()
	assert.Contains(t, output, "Status: FAILED")
	assert.Contains(t, output, "Error: scan failed: some error")
}

func TestScanResult_Duration(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Scan([]string{"."})

	// Duration should be recorded
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestConvertToScanResult(t *testing.T) {
	ar := &poutine.AnalysisResult{
		Success:          true,
		Target:           "/test/path",
		Repository:       "owner/repo",
		TotalFindings:    1,
		CriticalFindings: 1,
		Findings: []poutine.Finding{
			{
				ID:          "V001",
				Repository:  "owner/repo",
				Workflow:    ".github/workflows/ci.yml",
				Line:        10,
				RuleID:      "injection",
				Title:       "Injection",
				Severity:    "critical",
				Job:         "build",
				Step:        "run",
				Fingerprint: "abc123",
			},
		},
	}

	result := convertToScanResult(ar)

	assert.True(t, result.Success)
	assert.Equal(t, "/test/path", result.Path)
	assert.Equal(t, "owner/repo", result.Repository)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "injection", result.Findings[0].RuleID)
	assert.Equal(t, ".github/workflows/ci.yml", result.Findings[0].Path)
	assert.Contains(t, result.Rules, "injection")
}
