// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalScanResult_ValidJSON(t *testing.T) {
	json := `{
		"success": true,
		"duration_ms": 1234.5,
		"path": "/path/to/repo",
		"repository": "org/repo",
		"total_findings": 2,
		"critical_findings": 1,
		"high_findings": 1,
		"findings": [
			{
				"rule_id": "injection",
				"title": "Command Injection",
				"severity": "error",
				"path": ".github/workflows/ci.yml",
				"line": 42,
				"job": "build",
				"step": "run script"
			},
			{
				"rule_id": "untrusted_checkout_exec",
				"title": "Untrusted Checkout",
				"severity": "warning",
				"path": ".github/workflows/pr.yml",
				"line": 15
			}
		]
	}`

	result, err := UnmarshalScanResult([]byte(json))
	require.NoError(t, err)

	assert.True(t, result.Success)
	assert.Equal(t, 1234.5, result.Duration)
	assert.Equal(t, "/path/to/repo", result.Path)
	assert.Equal(t, "org/repo", result.Repository)
	assert.Equal(t, 2, result.TotalFindings)
	assert.Equal(t, 1, result.CriticalFindings)
	assert.Equal(t, 1, result.HighFindings)
	assert.Len(t, result.Findings, 2)

	// Check first finding
	f := result.Findings[0]
	assert.Equal(t, "injection", f.RuleID)
	assert.Equal(t, "Command Injection", f.Title)
	assert.Equal(t, "error", f.Severity)
	assert.Equal(t, ".github/workflows/ci.yml", f.Path)
	assert.Equal(t, 42, f.Line)
	assert.Equal(t, "build", f.Job)
	assert.Equal(t, "run script", f.Step)
}

func TestUnmarshalScanResult_InvalidJSON(t *testing.T) {
	_, err := UnmarshalScanResult([]byte("not json"))
	assert.Error(t, err)
}

func TestUnmarshalScanResult_EmptyJSON(t *testing.T) {
	result, err := UnmarshalScanResult([]byte("{}"))
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.Empty(t, result.Path)
	assert.Zero(t, result.TotalFindings)
}

func TestScanResult_HasFindings(t *testing.T) {
	tests := []struct {
		name     string
		total    int
		expected bool
	}{
		{"no findings", 0, false},
		{"has findings", 5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ScanResult{TotalFindings: tt.total}
			assert.Equal(t, tt.expected, r.HasFindings())
		})
	}
}

func TestScanResult_HasCritical(t *testing.T) {
	tests := []struct {
		name     string
		critical int
		expected bool
	}{
		{"no critical", 0, false},
		{"has critical", 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ScanResult{CriticalFindings: tt.critical}
			assert.Equal(t, tt.expected, r.HasCritical())
		})
	}
}

func TestScanResult_HasHigh(t *testing.T) {
	tests := []struct {
		name     string
		high     int
		expected bool
	}{
		{"no high", 0, false},
		{"has high", 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ScanResult{HighFindings: tt.high}
			assert.Equal(t, tt.expected, r.HasHigh())
		})
	}
}

func TestScanFinding_Structure(t *testing.T) {
	f := ScanFinding{
		RuleID:      "injection",
		Title:       "Test Title",
		Description: "Test Description",
		Severity:    "error",
		Path:        "/path/to/workflow.yml",
		Line:        100,
		Job:         "test-job",
		Step:        "test-step",
		OSVID:       "GHSA-1234",
		Details:     "Some details",
		Fingerprint: "abc123",
	}

	assert.Equal(t, "injection", f.RuleID)
	assert.Equal(t, "Test Title", f.Title)
	assert.Equal(t, "Test Description", f.Description)
	assert.Equal(t, "error", f.Severity)
	assert.Equal(t, "/path/to/workflow.yml", f.Path)
	assert.Equal(t, 100, f.Line)
	assert.Equal(t, "test-job", f.Job)
	assert.Equal(t, "test-step", f.Step)
	assert.Equal(t, "GHSA-1234", f.OSVID)
	assert.Equal(t, "Some details", f.Details)
	assert.Equal(t, "abc123", f.Fingerprint)
}

func TestOrder_MarkFailed(t *testing.T) {
	order := NewOrder("s1", "a1", "exec", nil)

	order.MarkFailed()
	assert.Equal(t, OrderStatusFailed, order.Status)
	assert.False(t, order.UpdatedAt.IsZero())
}

func TestScanResult_Marshal(t *testing.T) {
	r := &ScanResult{
		Success:       true,
		Path:          "/repo",
		TotalFindings: 1,
	}

	data, err := r.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), `"success":true`)
	assert.Contains(t, string(data), `"total_findings":1`)
}

func TestScanResult_FormatOutput_Success(t *testing.T) {
	r := &ScanResult{
		Success:          true,
		Path:             "/path/to/repo",
		Repository:       "acme/app",
		TotalFindings:    3,
		CriticalFindings: 1,
		HighFindings:     1,
		MediumFindings:   1,
		Duration:         500,
		Findings: []ScanFinding{
			{RuleID: "injection", Title: "Injection", Severity: "error", Path: "ci.yml", Line: 42, Job: "build", Step: "run"},
			{RuleID: "checkout", Title: "Checkout", Severity: "warning", Path: "pr.yml"},
		},
	}

	out := r.FormatOutput()
	assert.Contains(t, out, "Poutine Scan: /path/to/repo")
	assert.Contains(t, out, "Repository: acme/app")
	assert.Contains(t, out, "Total findings: 3")
	assert.Contains(t, out, "Critical: 1")
	assert.Contains(t, out, "High: 1")
	assert.Contains(t, out, "Medium: 1")
	assert.Contains(t, out, "[error] Injection")
	assert.Contains(t, out, "ci.yml:42")
	assert.Contains(t, out, "Job: build / Step: run")
	assert.Contains(t, out, "500ms")
}

func TestScanResult_FormatOutput_Failed(t *testing.T) {
	r := &ScanResult{
		Success: false,
		Path:    "/repo",
		Errors:  []string{"timeout", "network error"},
	}

	out := r.FormatOutput()
	assert.Contains(t, out, "FAILED")
	assert.Contains(t, out, "timeout")
	assert.Contains(t, out, "network error")
}

func TestScanResult_WithErrors(t *testing.T) {
	json := `{
		"success": false,
		"path": "/path/to/repo",
		"errors": ["error 1", "error 2"]
	}`

	result, err := UnmarshalScanResult([]byte(json))
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.Len(t, result.Errors, 2)
	assert.Equal(t, "error 1", result.Errors[0])
	assert.Equal(t, "error 2", result.Errors[1])
}
