// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package poutine provides shared poutine CI/CD security analysis functionality.
// This package is used by both Kitchen (remote analysis) and Brisket (local analysis).
package poutine

// OffensiveRules are poutine rules focused on initial access attack vectors.
// These rules identify vulnerabilities that can be exploited to gain code execution
// in CI/CD pipelines from an unauthenticated or low-privileged position.
//
// This is the single source of truth for offensive rules across the codebase.
var OffensiveRules = []string{
	// Command/script injection from untrusted input (PR titles, branch names, etc.)
	// Enables: Direct code execution via crafted input
	"injection",

	// PRs from forks running on self-hosted runners
	// Enables: Host compromise, lateral movement, persistent access
	"pr_runs_on_self_hosted",

	// Pwn Request: Untrusted code checkout followed by execution
	// Pattern: pull_request_target + checkout PR head + run build/script
	// Enables: Code execution via malicious PR content
	"untrusted_checkout_exec",
}

// ExtendedRules adds post-exploitation relevant rules for comprehensive analysis.
// These are useful for understanding the full attack surface but are not
// strictly "initial access" vectors.
var ExtendedRules = []string{
	// Debug/step-debug enabled allows OIDC token theft
	"debug_enabled",

	// Excessive permissions (write access, admin) expand blast radius
	"excessive_permissions",
}
