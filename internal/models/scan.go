// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package models contains domain models for SmokedMeat.
package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ScanResult represents the result of a poutine CI/CD security scan.
// This is the wire format used by Brisket to send results to Counter.
type ScanResult struct {
	Success  bool    `json:"success"`
	Duration float64 `json:"duration_ms"`

	// Scan metadata
	Path       string `json:"path"`
	Repository string `json:"repository,omitempty"`

	// Findings summary
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`

	// Detailed findings
	Findings []ScanFinding       `json:"findings,omitempty"`
	Rules    map[string]ScanRule `json:"rules,omitempty"`

	// Errors (non-fatal issues during scan)
	Errors []string `json:"errors,omitempty"`
}

// ScanFinding represents a single security finding from poutine.
type ScanFinding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line,omitempty"`
	Job         string `json:"job,omitempty"`
	Step        string `json:"step,omitempty"`
	OSVID       string `json:"osv_id,omitempty"`
	Details     string `json:"details,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ScanRule represents a poutine security rule.
type ScanRule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	References  []string `json:"refs,omitempty"`
}

// UnmarshalScanResult deserializes a ScanResult from JSON.
func UnmarshalScanResult(data []byte) (*ScanResult, error) {
	var r ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// HasFindings returns true if the scan found any vulnerabilities.
func (r *ScanResult) HasFindings() bool {
	return r.TotalFindings > 0
}

// HasCritical returns true if any critical findings were found.
func (r *ScanResult) HasCritical() bool {
	return r.CriticalFindings > 0
}

// HasHigh returns true if any high severity findings were found.
func (r *ScanResult) HasHigh() bool {
	return r.HighFindings > 0
}

// Marshal serializes a ScanResult to JSON.
func (r *ScanResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// FormatOutput returns a human-readable summary of the scan.
func (r *ScanResult) FormatOutput() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Poutine Scan: %s\n", r.Path)
	if r.Repository != "" {
		fmt.Fprintf(&sb, "  Repository: %s\n", r.Repository)
	}

	if !r.Success {
		sb.WriteString("  Status: FAILED\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&sb, "  Error: %s\n", e)
		}
		return sb.String()
	}

	fmt.Fprintf(&sb, "  Total findings: %d\n", r.TotalFindings)
	if r.CriticalFindings > 0 {
		fmt.Fprintf(&sb, "  Critical: %d\n", r.CriticalFindings)
	}
	if r.HighFindings > 0 {
		fmt.Fprintf(&sb, "  High: %d\n", r.HighFindings)
	}
	if r.MediumFindings > 0 {
		fmt.Fprintf(&sb, "  Medium: %d\n", r.MediumFindings)
	}
	if r.LowFindings > 0 {
		fmt.Fprintf(&sb, "  Low: %d\n", r.LowFindings)
	}

	for _, f := range r.Findings {
		fmt.Fprintf(&sb, "\n  [%s] %s\n", f.Severity, f.Title)
		fmt.Fprintf(&sb, "    Path: %s", f.Path)
		if f.Line > 0 {
			fmt.Fprintf(&sb, ":%d", f.Line)
		}
		sb.WriteString("\n")
		if f.Job != "" {
			fmt.Fprintf(&sb, "    Job: %s", f.Job)
			if f.Step != "" {
				fmt.Fprintf(&sb, " / Step: %s", f.Step)
			}
			sb.WriteString("\n")
		}
	}

	fmt.Fprintf(&sb, "\n  Scan completed in %.0fms\n", r.Duration)
	return sb.String()
}
