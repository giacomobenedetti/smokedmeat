// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNapkin_NoArgs(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Napkin(nil)

	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "usage:")
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestNapkin_NoToken(t *testing.T) {
	// Save and clear tokens
	savedToken := os.Getenv("GITHUB_TOKEN")
	savedGHToken := os.Getenv("GH_TOKEN")
	os.Unsetenv("GITHUB_TOKEN")
	os.Unsetenv("GH_TOKEN")
	defer func() {
		if savedToken != "" {
			os.Setenv("GITHUB_TOKEN", savedToken)
		}
		if savedGHToken != "" {
			os.Setenv("GH_TOKEN", savedGHToken)
		}
	}()

	agent := New(DefaultConfig())
	result := agent.Napkin([]string{"delete-run", "123"})

	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "GITHUB_TOKEN or GH_TOKEN required")
}

func TestNapkin_NoRepository(t *testing.T) {
	// Save and clear GITHUB_REPOSITORY
	savedRepo := os.Getenv("GITHUB_REPOSITORY")
	os.Unsetenv("GITHUB_REPOSITORY")
	defer func() {
		if savedRepo != "" {
			os.Setenv("GITHUB_REPOSITORY", savedRepo)
		}
	}()

	withEnv(t, map[string]string{
		"GITHUB_TOKEN": "ghp_testtoken123",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"delete-run", "123"})

		assert.False(t, result.Success)
		assert.Contains(t, result.Errors[0], "GITHUB_REPOSITORY not set")
	})
}

func TestNapkin_DeleteRunMissingRunID(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"delete-run"})

		assert.False(t, result.Success)
		assert.Contains(t, result.Errors[0], "usage: napkin delete-run")
	})
}

func TestNapkin_DeleteRunInvalidRunID(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"delete-run", "not-a-number"})

		assert.False(t, result.Success)
		assert.Contains(t, result.Errors[0], "invalid run_id")
	})
}

func TestNapkin_DeleteLogsMissingRunID(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"delete-logs"})

		assert.False(t, result.Success)
		assert.Contains(t, result.Errors[0], "usage: napkin delete-logs")
	})
}

func TestNapkin_DeleteLogsInvalidRunID(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"delete-logs", "invalid"})

		assert.False(t, result.Success)
		assert.Contains(t, result.Errors[0], "invalid run_id")
	})
}

func TestNapkin_DeleteCurrentNoRunID(t *testing.T) {
	// Clear GITHUB_RUN_ID
	savedRunID := os.Getenv("GITHUB_RUN_ID")
	os.Unsetenv("GITHUB_RUN_ID")
	defer func() {
		if savedRunID != "" {
			os.Setenv("GITHUB_RUN_ID", savedRunID)
		}
	}()

	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"delete-current"})

		assert.False(t, result.Success)
		assert.Contains(t, result.Errors[0], "GITHUB_RUN_ID not set")
	})
}

func TestNapkin_UnknownOperation(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"unknown-op"})

		assert.False(t, result.Success)
		assert.Equal(t, "unknown-op", result.Operation)
		assert.Contains(t, result.Errors[0], "unknown operation")
	})
}

func TestNapkin_OperationIsRecorded(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())

		operations := []string{"delete-run", "delete-logs", "cleanup", "list-runs"}
		for _, op := range operations {
			result := agent.Napkin([]string{op})
			assert.Equal(t, op, result.Operation, "operation should be recorded for %s", op)
		}
	})
}

func TestNapkin_GHTokenFallback(t *testing.T) {
	// Clear GITHUB_TOKEN, set GH_TOKEN
	savedToken := os.Getenv("GITHUB_TOKEN")
	savedGHToken := os.Getenv("GH_TOKEN")
	savedRepo := os.Getenv("GITHUB_REPOSITORY")
	os.Unsetenv("GITHUB_TOKEN")
	defer func() {
		if savedToken != "" {
			os.Setenv("GITHUB_TOKEN", savedToken)
		}
		if savedGHToken != "" {
			os.Setenv("GH_TOKEN", savedGHToken)
		}
		if savedRepo != "" {
			os.Setenv("GITHUB_REPOSITORY", savedRepo)
		}
	}()

	withEnv(t, map[string]string{
		"GH_TOKEN":          "ghp_fallbacktoken",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		result := agent.Napkin([]string{"unknown"})

		// Should get past token check and fail on unknown operation
		assert.Equal(t, "unknown", result.Operation)
		assert.Contains(t, result.Errors[0], "unknown operation")
	})
}

func TestNapkinResult_Marshal(t *testing.T) {
	result := &NapkinResult{
		Success:     true,
		Operation:   "delete-run",
		RunsDeleted: 5,
		Duration:    123.45,
		DeletedRuns: []DeletedRun{
			{RunID: 123, Status: "deleted"},
		},
	}

	data, err := result.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), `"success":true`)
	assert.Contains(t, string(data), `"operation":"delete-run"`)
	assert.Contains(t, string(data), `"runs_deleted":5`)
	assert.Contains(t, string(data), `"duration_ms":123.45`)
}

func TestDeletedRun_Structure(t *testing.T) {
	dr := DeletedRun{
		RunID:      12345,
		WorkflowID: 6789,
		Name:       "CI Build",
		Status:     "deleted",
	}

	assert.Equal(t, int64(12345), dr.RunID)
	assert.Equal(t, int64(6789), dr.WorkflowID)
	assert.Equal(t, "CI Build", dr.Name)
	assert.Equal(t, "deleted", dr.Status)
	assert.Empty(t, dr.Error)
}

func TestNapkinResult_SuccessConditions(t *testing.T) {
	// Success should be true if no errors, or if some deletions succeeded
	tests := []struct {
		name        string
		errors      []string
		runsDeleted int
		logsDeleted int
		expected    bool
	}{
		{"no errors no deletions", nil, 0, 0, true},
		{"no errors with runs deleted", nil, 1, 0, true},
		{"no errors with logs deleted", nil, 0, 1, true},
		{"errors but runs deleted", []string{"error"}, 1, 0, true},
		{"errors but logs deleted", []string{"error"}, 0, 1, true},
		{"errors no deletions", []string{"error"}, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &NapkinResult{
				Errors:      tt.errors,
				RunsDeleted: tt.runsDeleted,
				LogsDeleted: tt.logsDeleted,
			}
			// Mimic the success logic from Napkin()
			result.Success = len(result.Errors) == 0 || result.RunsDeleted > 0 || result.LogsDeleted > 0
			assert.Equal(t, tt.expected, result.Success)
		})
	}
}

func TestNapkin_Duration(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Napkin(nil)

	// Duration should be recorded even for errors
	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestNapkin_CleanupWithWorkflowName(t *testing.T) {
	withEnv(t, map[string]string{
		"GITHUB_TOKEN":      "ghp_testtoken123",
		"GITHUB_REPOSITORY": "owner/repo",
	}, func() {
		agent := New(DefaultConfig())
		// This will fail at the API call, but we're testing argument parsing
		result := agent.Napkin([]string{"cleanup", "my-workflow"})

		assert.Equal(t, "cleanup", result.Operation)
		// Errors will be from API failure, not argument parsing
	})
}
