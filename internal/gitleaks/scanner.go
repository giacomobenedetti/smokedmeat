// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gitleaks

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/semgroup"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	glregexp "github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// SecretFinding represents a secret discovered by gitleaks.
type SecretFinding struct {
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description"`
	File        string  `json:"file"`
	StartLine   int     `json:"start_line"`
	Secret      string  `json:"secret"`
	Fingerprint string  `json:"fingerprint"`
	Entropy     float32 `json:"entropy"`
}

// ScanResult contains all findings from a gitleaks scan.
type ScanResult struct {
	Findings []SecretFinding `json:"findings"`
	RepoPath string          `json:"repo_path"`
}

var scanConfig = config.Config{
	Rules: map[string]config.Rule{
		"private-key": {
			RuleID:      "private-key",
			Description: "Private Key detected",
			Regex:       glregexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`),
			Keywords:    []string{"-----begin"},
		},
		"github-pat": {
			RuleID:      "github-pat",
			Description: "GitHub Personal Access Token",
			Regex:       glregexp.MustCompile(`ghp_[A-Za-z0-9]{36,255}`),
			Keywords:    []string{"ghp_"},
		},
		"github-fine-grained-pat": {
			RuleID:      "github-fine-grained-pat",
			Description: "GitHub Fine-Grained PAT",
			Regex:       glregexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`),
			Keywords:    []string{"github_pat_"},
		},
		"pkcs12-file": {
			RuleID:      "pkcs12-file",
			Description: "PKCS#12 file detected",
			Path:        glregexp.MustCompile(`(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$`),
		},
	},
	Keywords: map[string]struct{}{
		"-----begin":  {},
		"ghp_":        {},
		"github_pat_": {},
	},
}

// ScanDirectory scans a local directory for private keys and certificate files.
func ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
	detector := detect.NewDetector(scanConfig)

	findings, err := detector.DetectSource(ctx, &sources.Files{
		Path:   dir,
		Config: &detector.Config,
		Sema:   semgroup.NewGroup(ctx, 20),
	})
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan failed: %w", err)
	}

	result := &ScanResult{RepoPath: dir}
	for _, f := range findings {
		result.Findings = append(result.Findings, toSecretFinding(f))
	}

	return result, nil
}

// CloneAndScan clones a repository and scans it for secrets.
// Uses init+fetch with a credential helper to keep the token out of
// .git/config. Inspired by poutine's gitops credential helper pattern.
func CloneAndScan(ctx context.Context, token, target string) (*ScanResult, error) {
	tmpDir, err := os.MkdirTemp("", "gitleaks-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "repo")
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create repo dir: %w", err)
	}

	cloneURL := fmt.Sprintf("https://github.com/%s.git", target)
	credHelper := `!f() { test "$1" = get && echo "username=x-access-token" && echo "password=$GITLEAKS_CLONE_TOKEN"; }; f`
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GITLEAKS_CLONE_TOKEN="+token)

	git := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = repoDir
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %w (%s)", args[0], err, sanitizeOutput(output, token))
		}
		return nil
	}

	for _, step := range [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", cloneURL},
		{"config", "credential.helper", credHelper},
		{"fetch", "--quiet", "--depth", "1", "origin"},
		{"checkout", "--quiet", "-b", "scan", "FETCH_HEAD"},
	} {
		if err := git(step...); err != nil {
			return nil, err
		}
	}

	slog.Info("scanning repo for secrets", "target", target)
	return ScanDirectory(ctx, repoDir)
}

func toSecretFinding(f report.Finding) SecretFinding {
	return SecretFinding{
		RuleID:      f.RuleID,
		Description: f.Description,
		File:        f.File,
		StartLine:   f.StartLine,
		Secret:      f.Secret,
		Fingerprint: f.Fingerprint,
		Entropy:     f.Entropy,
	}
}

// sanitizeOutput removes token from git output to prevent leaking.
func sanitizeOutput(output []byte, token string) string {
	s := string(output)
	if token != "" {
		s = strings.ReplaceAll(s, token, "***")
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
