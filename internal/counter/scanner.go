// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package counter implements the Counter operator interface components.
package counter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

// Client is a thin client for interacting with Kitchen's analysis endpoints.
// Counter delegates all heavy lifting (poutine analysis) to Kitchen.
type Client struct {
	KitchenURL string
	AuthToken  string
	SessionID  string
	HTTPClient *http.Client
}

// NewClient creates a new Kitchen client. SessionID is required —
// Kitchen uses it to track known entities and repo visibility.
func NewClient(kitchenURL, authToken, sessionID string) *Client {
	return &Client{
		KitchenURL: kitchenURL,
		AuthToken:  authToken,
		SessionID:  sessionID,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Minute,
		},
	}
}

// AnalyzeRequest is the request body for the /analyze endpoint.
type AnalyzeRequest struct {
	// Token is the GitHub token for API access.
	// SECURITY: This is the OPERATOR's token, used ephemerally by Kitchen.
	// It is NOT stored as loot.
	Token string `json:"token"`

	// Target is the org or org/repo to analyze.
	Target string `json:"target"`

	// TargetType is "org" or "repo".
	TargetType string `json:"target_type"`

	// Deep enables gitleaks scanning for private keys.
	Deep bool `json:"deep,omitempty"`

	// SessionID identifies the operator session (for known entity lookups).
	SessionID string `json:"session_id,omitempty"`
}

// Analyze performs a poutine analysis by delegating to Kitchen.
// The token is sent to Kitchen for ephemeral use - it is never stored.
func (c *Client) Analyze(ctx context.Context, token, target, targetType string) (*poutine.AnalysisResult, error) {
	return c.analyze(ctx, token, target, targetType, false)
}

// DeepAnalyze performs poutine analysis plus gitleaks secret scanning.
func (c *Client) DeepAnalyze(ctx context.Context, token, target, targetType string) (*poutine.AnalysisResult, error) {
	return c.analyze(ctx, token, target, targetType, true)
}

func (c *Client) analyze(ctx context.Context, token, target, targetType string, deep bool) (*poutine.AnalysisResult, error) {
	if c.KitchenURL == "" {
		return nil, fmt.Errorf("kitchen URL not configured")
	}

	reqBody := AnalyzeRequest{
		Token:      token,
		Target:     target,
		TargetType: targetType,
		Deep:       deep,
		SessionID:  c.SessionID,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/analyze", c.KitchenURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Kitchen: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kitchen returned error: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var result poutine.AnalysisResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}
