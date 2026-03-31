// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/lotp"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

// InjectResult represents the result of payload generation.
type InjectResult struct {
	Success  bool            `json:"success"`
	Context  string          `json:"context"`
	Payloads []PayloadOutput `json:"payloads"`
	Errors   []string        `json:"errors,omitempty"`
}

// PayloadOutput is a generated payload ready to use.
type PayloadOutput struct {
	Raw       string `json:"raw"`
	Technique string `json:"technique"`
	Notes     string `json:"notes,omitempty"`
}

// LOTPResult represents the result of LOTP analysis and payload generation.
type LOTPResult struct {
	Success           bool                    `json:"success"`
	DetectedVectors   []string                `json:"detected_vectors"`
	RecommendedVector string                  `json:"recommended_vector,omitempty"`
	Payloads          []lotp.GeneratedPayload `json:"payloads,omitempty"`
	Errors            []string                `json:"errors,omitempty"`
}

// Inject generates injection payloads for the specified context.
// Usage: inject <context> <command>
// Contexts: pr_title, pr_body, git_branch, commit_message, github_script, bash_run
func (a *Agent) Inject(args []string) *InjectResult {
	result := &InjectResult{
		Payloads: []PayloadOutput{},
		Errors:   []string{},
	}

	if len(args) < 2 {
		result.Errors = append(result.Errors,
			"usage: inject <context> <command>",
			"contexts: pr_title, pr_body, git_branch, commit_message, github_script, bash_run")
		return result
	}

	contextName := args[0]
	command := strings.Join(args[1:], " ")

	ctx, ok := rye.GetContextByName(contextName)
	if !ok {
		result.Errors = append(result.Errors,
			fmt.Sprintf("unknown context: %s", contextName),
			"available: pr_title, pr_body, git_branch, commit_message, github_script, bash_run")
		return result
	}

	result.Context = contextName
	gen := rye.NewGenerator(ctx)
	payloads := gen.Generate(command)

	for _, p := range payloads {
		result.Payloads = append(result.Payloads, PayloadOutput{
			Raw:       p.Raw,
			Technique: p.Technique,
			Notes:     p.Notes,
		})
	}

	result.Success = len(result.Payloads) > 0
	return result
}

// LOTP detects available Living Off The Pipeline vectors and generates payloads.
// Usage:
//
//	lotp detect              - Detect available vectors in current directory
//	lotp generate <technique> <command> [callback_url] - Generate payload
//	lotp list                - List all known techniques
func (a *Agent) LOTP(args []string) *LOTPResult {
	result := &LOTPResult{
		DetectedVectors: []string{},
		Payloads:        []lotp.GeneratedPayload{},
		Errors:          []string{},
	}

	if len(args) == 0 {
		args = []string{"detect"}
	}

	subcommand := args[0]

	switch subcommand {
	case "detect":
		result = a.lotpDetect()
	case "generate", "gen":
		if len(args) < 3 {
			result.Errors = append(result.Errors, "usage: lotp generate <technique> <command> [callback_url]")
			return result
		}
		technique := args[1]
		command := args[2]
		callbackURL := ""
		if len(args) > 3 {
			callbackURL = args[3]
		}
		result = a.lotpGenerate(technique, command, callbackURL)
	case "list":
		result = a.lotpList()
	default:
		result.Errors = append(result.Errors,
			fmt.Sprintf("unknown subcommand: %s", subcommand),
			"usage: lotp [detect|generate|list]")
	}

	return result
}

// lotpDetect scans the current directory for available LOTP vectors.
func (a *Agent) lotpDetect() *LOTPResult {
	result := &LOTPResult{
		DetectedVectors: []string{},
		Payloads:        []lotp.GeneratedPayload{},
		Errors:          []string{},
	}

	// Get files in current directory
	cwd, err := os.Getwd()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to get cwd: %v", err))
		return result
	}

	var files []string
	err = filepath.Walk(cwd, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		// Skip .git and node_modules
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			// Get relative path
			rel, _ := filepath.Rel(cwd, path)
			files = append(files, filepath.Base(rel))
		}
		return nil
	})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to walk directory: %v", err))
	}

	// Detect techniques based on files
	techniques := lotp.DetectAvailableVectors(files, nil)
	for _, t := range techniques {
		result.DetectedVectors = append(result.DetectedVectors, t.Name)
	}

	// Recommend best payload
	if len(techniques) > 0 {
		opts := lotp.PayloadOptions{Command: "id"}
		best := lotp.RecommendBestPayload(techniques, opts)
		if best != nil {
			result.RecommendedVector = best.Technique
		}
	}

	result.Success = true
	return result
}

// lotpGenerate generates payloads for a specific technique.
func (a *Agent) lotpGenerate(technique, command, callbackURL string) *LOTPResult {
	result := &LOTPResult{
		DetectedVectors: []string{},
		Payloads:        []lotp.GeneratedPayload{},
		Errors:          []string{},
	}

	opts := lotp.PayloadOptions{
		Command:     command,
		CallbackURL: callbackURL,
	}

	var payloads []lotp.GeneratedPayload

	switch strings.ToLower(technique) {
	case "npm":
		payloads = lotp.NewNPMPayload(opts).Generate()
	case "pip", "python":
		payloads = lotp.NewPipPayload(opts).Generate()
	case "yarn":
		payloads = lotp.NewYarnPayload(opts).Generate()
	case "cargo", "rust":
		payloads = lotp.NewCargoPayload(opts).Generate()
	case "make":
		payloads = lotp.NewMakePayload(opts).Generate()
	default:
		result.Errors = append(result.Errors,
			fmt.Sprintf("unsupported technique: %s", technique),
			"supported: npm, pip, yarn, cargo, make")
		return result
	}

	result.Payloads = payloads
	result.Success = len(payloads) > 0
	return result
}

// lotpList lists all known LOTP techniques.
func (a *Agent) lotpList() *LOTPResult {
	result := &LOTPResult{
		DetectedVectors: []string{},
		Payloads:        []lotp.GeneratedPayload{},
		Errors:          []string{},
	}

	techniques := lotp.AllTechniques()
	for _, t := range techniques {
		result.DetectedVectors = append(result.DetectedVectors, t.Name)
	}

	result.Success = true
	return result
}

// Marshal serializes an InjectResult to JSON.
func (r *InjectResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// Marshal serializes a LOTPResult to JSON.
func (r *LOTPResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
