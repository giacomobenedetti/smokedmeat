// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package brisket implements the implant/agent that runs on target systems.
package brisket

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

// Scan performs a poutine CI/CD security scan on the specified path.
// This uses the shared poutine package for analysis and returns a models.ScanResult
// for wire-format compatibility with Counter.
func (a *Agent) Scan(args []string) *models.ScanResult {
	start := time.Now()

	// Determine path to scan
	path := "."
	if len(args) > 0 && args[0] != "" {
		path = args[0]
	}

	// Try to get workspace from environment
	if path == "." {
		if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
			path = workspace
		} else if workspace := os.Getenv("CI_PROJECT_DIR"); workspace != "" {
			path = workspace
		}
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return &models.ScanResult{
			Success:  false,
			Path:     path,
			Duration: float64(time.Since(start).Milliseconds()),
			Errors:   []string{"failed to resolve path: " + err.Error()},
		}
	}

	// Run analysis using shared poutine package
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	analysisResult, err := poutine.AnalyzeLocal(ctx, absPath)
	if err != nil {
		return &models.ScanResult{
			Success:  false,
			Path:     absPath,
			Duration: float64(time.Since(start).Milliseconds()),
			Errors:   []string{"analysis failed: " + err.Error()},
		}
	}

	// Convert poutine.AnalysisResult to models.ScanResult for wire format
	return convertToScanResult(analysisResult)
}

// convertToScanResult converts a poutine.AnalysisResult to models.ScanResult.
// This maintains wire-format compatibility with Counter TUI.
func convertToScanResult(ar *poutine.AnalysisResult) *models.ScanResult {
	result := &models.ScanResult{
		Success:          ar.Success,
		Duration:         float64(ar.Duration.Milliseconds()),
		Path:             ar.Target,
		Repository:       ar.Repository,
		TotalFindings:    ar.TotalFindings,
		CriticalFindings: ar.CriticalFindings,
		HighFindings:     ar.HighFindings,
		MediumFindings:   ar.MediumFindings,
		LowFindings:      ar.LowFindings,
		Errors:           ar.Errors,
		Findings:         make([]models.ScanFinding, 0, len(ar.Findings)),
		Rules:            make(map[string]models.ScanRule),
	}

	// Convert findings
	for _, f := range ar.Findings {
		result.Findings = append(result.Findings, models.ScanFinding{
			RuleID:      f.RuleID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			Path:        f.Workflow,
			Line:        f.Line,
			Job:         f.Job,
			Step:        f.Step,
			Details:     f.Details,
			Fingerprint: f.Fingerprint,
		})

		// Add rule if not already present
		if _, ok := result.Rules[f.RuleID]; !ok && f.Title != "" {
			result.Rules[f.RuleID] = models.ScanRule{
				ID:          f.RuleID,
				Title:       f.Title,
				Description: f.Description,
				Severity:    f.Severity,
			}
		}
	}

	return result
}
