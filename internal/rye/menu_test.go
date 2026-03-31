// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package rye

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLightRye(t *testing.T) {
	lr := NewLightRye("http://kitchen.example.com")

	assert.Equal(t, "http://kitchen.example.com", lr.KitchenURL)
	assert.Equal(t, ModeFullAuto, lr.Mode)
}

func TestLightRye_SetMode(t *testing.T) {
	lr := NewLightRye("http://k.io")

	lr.SetMode(ModeManual)
	assert.Equal(t, ModeManual, lr.Mode)

	lr.SetMode(ModeSemiAuto)
	assert.Equal(t, ModeSemiAuto, lr.Mode)

	lr.SetMode(ModeFullAuto)
	assert.Equal(t, ModeFullAuto, lr.Mode)
}

func TestLightRye_Menu(t *testing.T) {
	lr := NewLightRye("http://k.io")
	menu := lr.Menu()

	assert.NotEmpty(t, menu)

	// Check we have expected menu items
	ids := make(map[string]bool)
	for _, item := range menu {
		ids[item.ID] = true

		// Each item should be fully populated
		assert.NotEmpty(t, item.ID)
		assert.NotEmpty(t, item.Name)
		assert.NotEmpty(t, item.Context)
		assert.NotEmpty(t, item.Description)
		assert.NotEmpty(t, item.Payload.Raw)
		assert.NotEmpty(t, item.Preview)
	}

	// Should have key injection contexts
	assert.True(t, ids["branch_ifs"], "Menu should have branch IFS")
	assert.True(t, ids["pr_title"], "Menu should have PR title")
	assert.True(t, ids["pr_body"], "Menu should have PR body")
	assert.True(t, ids["github_script"], "Menu should have GitHub Script")
}

func TestLightRye_Menu_PayloadsAreValid(t *testing.T) {
	lr := NewLightRye("http://k.io")
	menu := lr.Menu()

	for _, item := range menu {
		// Payload should contain the kitchen URL
		assert.Contains(t, item.Payload.CallbackURL, "http://k.io",
			"Item %s should have valid callback URL", item.ID)

		// Preview should be truncated version of payload
		if len(item.Payload.Raw) > 60 {
			assert.True(t, len(item.Preview) <= 63,
				"Preview for %s should be truncated", item.ID)
		}
	}
}

func TestLightRye_Insight(t *testing.T) {
	lr := NewLightRye("http://k.io")

	// Valid context
	insight, err := lr.Insight("pr_title")
	assert.NoError(t, err)
	assert.NotNil(t, insight)
	assert.Equal(t, "pr_title", insight.Context)
	assert.True(t, insight.IsPossible)
	assert.NotEmpty(t, insight.Template)
	assert.NotEmpty(t, insight.Constraints)
	assert.NotEmpty(t, insight.Placeholders)
	assert.NotEmpty(t, insight.Suggestions)

	// Invalid context
	_, err = lr.Insight("invalid")
	assert.Error(t, err)
}

func TestLightRye_Insight_JS(t *testing.T) {
	lr := NewLightRye("http://k.io")

	insight, err := lr.Insight("github_script")
	assert.NoError(t, err)

	// JS-specific suggestions
	found := false
	for _, s := range insight.Suggestions {
		if s == "Use process.mainModule.require for sandbox bypass" {
			found = true
			break
		}
	}
	assert.True(t, found, "JS insight should have JS-specific suggestions")
}

func TestLightRye_Insight_AllContexts(t *testing.T) {
	lr := NewLightRye("http://k.io")

	contexts := []string{
		"git_branch", "pr_title", "pr_body",
		"commit_message", "issue_title", "issue_body",
		"github_script", "bash_run",
	}

	for _, ctx := range contexts {
		insight, err := lr.Insight(ctx)
		assert.NoError(t, err, "Insight for %s should succeed", ctx)
		assert.NotNil(t, insight)
		assert.Equal(t, ctx, insight.Context)
	}
}

func TestLightRye_BuildingBlocks(t *testing.T) {
	lr := NewLightRye("http://k.io")
	blocks := lr.BuildingBlocks()

	assert.NotEmpty(t, blocks)

	// Check we have expected blocks
	names := make(map[string]bool)
	for _, block := range blocks {
		names[block.Name] = true

		// Each block should be fully populated
		assert.NotEmpty(t, block.Name)
		assert.NotEmpty(t, block.Template)
		assert.NotEmpty(t, block.Example)
		assert.NotEmpty(t, block.Description)
	}

	// Should have key building blocks
	assert.True(t, names["IFS_SPACE"], "Should have IFS_SPACE")
	assert.True(t, names["BASE64_URL"], "Should have BASE64_URL")
	assert.True(t, names["CURL_BASH"], "Should have CURL_BASH")
	assert.True(t, names["JS_QUOTE_POLYGLOT"], "Should have JS_QUOTE_POLYGLOT")
	assert.True(t, names["JS_BREAK_SINGLE"], "Should have JS_BREAK_SINGLE")
	assert.True(t, names["QUOTE_BREAK_DOUBLE"], "Should have QUOTE_BREAK_DOUBLE")
	assert.True(t, names["NEWLINE_INJECT"], "Should have NEWLINE_INJECT")
}

func TestLightRye_QuickStager(t *testing.T) {
	lr := NewLightRye("http://k.io")

	// Valid context
	payload, err := lr.QuickStager("pr_title")
	assert.NoError(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, "pr_title", payload.Context)
	assert.NotEmpty(t, payload.Raw)

	// Invalid context
	_, err = lr.QuickStager("invalid")
	assert.Error(t, err)
}

func TestTruncate(t *testing.T) {
	// Short string - no truncation
	assert.Equal(t, "hello", truncate("hello", 10))

	// Exact length - no truncation
	assert.Equal(t, "hello", truncate("hello", 5))

	// Long string - truncated
	result := truncate("hello world this is a long string", 10)
	assert.Equal(t, "hello w...", result)
	assert.Len(t, result, 10)
}
