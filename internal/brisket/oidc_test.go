// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

// createMockJWT creates a mock JWT token with the given claims.
func createMockJWT(claims map[string]interface{}) string {
	// Header (standard JWT header)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	// Payload
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Signature (mock)
	signature := base64.RawURLEncoding.EncodeToString([]byte("mock-signature"))

	return header + "." + payload + "." + signature
}

func TestDecodeJWTClaims_ValidToken(t *testing.T) {
	claims := map[string]interface{}{
		"iss":              "https://token.actions.githubusercontent.com",
		"sub":              "repo:acme/api:ref:refs/heads/main",
		"aud":              "sts.amazonaws.com",
		"exp":              1735689600.0,
		"iat":              1735686000.0,
		"repository":       "acme/api",
		"repository_owner": "acme",
		"workflow":         "CI",
		"actor":            "developer",
		"ref":              "refs/heads/main",
		"ref_type":         "branch",
		"run_id":           "12345",
		"environment":      "production",
		"job_workflow_ref": "acme/api/.github/workflows/ci.yml@refs/heads/main",
	}

	jwt := createMockJWT(claims)
	token := &OIDCToken{RawToken: jwt}

	err := decodeJWTClaims(token)
	require.NoError(t, err)

	assert.Equal(t, "https://token.actions.githubusercontent.com", token.Issuer)
	assert.Equal(t, "repo:acme/api:ref:refs/heads/main", token.Subject)
	assert.Equal(t, "sts.amazonaws.com", token.Audience)
	assert.Equal(t, int64(1735689600), token.ExpiresAt)
	assert.Equal(t, int64(1735686000), token.IssuedAt)
	assert.Equal(t, "acme/api", token.Repository)
	assert.Equal(t, "acme", token.RepositoryOwner)
	assert.Equal(t, "CI", token.Workflow)
	assert.Equal(t, "developer", token.Actor)
	assert.Equal(t, "refs/heads/main", token.Ref)
	assert.Equal(t, "branch", token.RefType)
	assert.Equal(t, "12345", token.RunID)
	assert.Equal(t, "production", token.Environment)
	assert.Equal(t, "acme/api/.github/workflows/ci.yml@refs/heads/main", token.JobWorkflowRef)

	// Verify all claims are stored
	assert.NotNil(t, token.AllClaims)
	assert.Len(t, token.AllClaims, 14)
}

func TestDecodeJWTClaims_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"one part", "header"},
		{"two parts", "header.payload"},
		{"four parts", "header.payload.signature.extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &OIDCToken{RawToken: tt.token}
			err := decodeJWTClaims(token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid JWT format")
		})
	}
}

func TestDecodeJWTClaims_InvalidBase64(t *testing.T) {
	// Invalid base64 in payload
	token := &OIDCToken{RawToken: "header.!!!invalid!!!.signature"}
	err := decodeJWTClaims(token)
	assert.Error(t, err)
}

func TestDecodeJWTClaims_InvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	token := &OIDCToken{RawToken: "header." + invalidJSON + ".signature"}
	err := decodeJWTClaims(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWT claims")
}

func TestDetectCloudProvider(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		issuer   string
		expected string
	}{
		// AWS
		{"AWS STS audience", "sts.amazonaws.com", "", "aws"},
		{"AWS URL audience", "https://sts.amazonaws.com", "", "aws"},

		// GCP
		{"Google audience", "https://iam.googleapis.com/project/123", "", "gcp"},
		{"GCP keyword", "my-gcp-project", "", "gcp"},

		// Azure
		{"Azure audience", "api://AzureADTokenExchange", "", "azure"},
		{"Microsoft audience", "https://login.microsoft.com", "", "azure"},

		// Kubernetes
		{"K8s audience", "https://kubernetes.default.svc", "", "k8s"},
		{"K8s keyword", "kubernetes.local", "", "k8s"},

		// GitLab (returns generic)
		{"GitLab issuer", "", "https://gitlab.com", "generic"},

		// Unknown
		{"Unknown audience", "custom-audience", "", "generic"},
		{"Empty audience", "", "", "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &OIDCToken{
				Audience: tt.audience,
				Issuer:   tt.issuer,
			}
			result := detectCloudProvider(token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectTargetAudiences(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		expected []string
	}{
		{"AWS STS", "sts.amazonaws.com", []string{"aws"}},
		{"GCP IAM", "https://iam.googleapis.com", []string{"gcp"}},
		{"Azure", "api://AzureADTokenExchange", []string{"azure"}},
		{"Kubernetes", "https://kubernetes.default", []string{"k8s"}},
		{"Sigstore", "sigstore", []string{"sigstore"}},
		{"Unknown", "custom-audience", nil},
		{"Empty", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &OIDCToken{Audience: tt.audience}
			result := detectTargetAudiences(token)
			if tt.expected == nil {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestOIDC_GitHubActionsNotAvailable(t *testing.T) {
	clearCIPlatformEnv(t)

	// Set GitHub Actions but no OIDC
	withEnv(t, map[string]string{
		"GITHUB_ACTIONS": "true",
	}, func() {
		agent := New(DefaultConfig())
		_, err := agent.OIDC("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OIDC not available")
	})
}

func TestOIDC_GitLabCINotAvailable(t *testing.T) {
	clearCIPlatformEnv(t)

	// Set GitLab CI but no OIDC token
	withEnv(t, map[string]string{
		"GITLAB_CI": "true",
	}, func() {
		agent := New(DefaultConfig())
		_, err := agent.OIDC("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OIDC not available")
	})
}

func TestOIDC_CircleCINotAvailable(t *testing.T) {
	clearCIPlatformEnv(t)

	// Set CircleCI but no OIDC token
	withEnv(t, map[string]string{
		"CIRCLECI": "true",
	}, func() {
		agent := New(DefaultConfig())
		_, err := agent.OIDC("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OIDC not available")
	})
}

func TestOIDC_AzureDevOpsNotAvailable(t *testing.T) {
	clearCIPlatformEnv(t)

	// Set Azure DevOps but no OIDC
	withEnv(t, map[string]string{
		"TF_BUILD": "True",
	}, func() {
		agent := New(DefaultConfig())
		_, err := agent.OIDC("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OIDC not available")
	})
}

func TestOIDC_UnknownPlatform(t *testing.T) {
	clearCIPlatformEnv(t)

	// No CI platform detected
	agent := New(DefaultConfig())
	_, err := agent.OIDC("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC not supported on platform")
}

func TestOIDCPivot_UnknownProvider(t *testing.T) {
	clearCIPlatformEnv(t)

	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"value":"mock.jwt.token"}`), nil
	})

	withEnv(t, map[string]string{
		"GITHUB_ACTIONS":                 "true",
		"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://mock.test/token",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-token",
	}, func() {
		cfg := DefaultConfig()
		cfg.HTTPClient = mockClient
		agent := New(cfg)
		result, err := agent.OIDCPivot("invalid-provider", nil)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})
}

func TestExtractGitLabOIDC_WithToken(t *testing.T) {
	clearCIPlatformEnv(t)

	claims := map[string]interface{}{
		"iss":            "https://gitlab.com",
		"sub":            "project_path:group/repo:ref_type:branch:ref:main",
		"aud":            "https://gitlab.example.com",
		"namespace_path": "group",
		"project_path":   "group/repo",
		"pipeline_id":    "12345",
		"job_id":         "67890",
	}
	mockToken := createMockJWT(claims)

	withEnv(t, map[string]string{
		"GITLAB_CI":     "true",
		"CI_JOB_JWT_V2": mockToken,
	}, func() {
		agent := New(DefaultConfig())
		token, err := agent.OIDC("")
		require.NoError(t, err)

		assert.Equal(t, models.PlatformGitLabCI, token.Platform)
		assert.Equal(t, "CI_JOB_JWT_V2", token.TokenSource)
		assert.Equal(t, "https://gitlab.com", token.Issuer)
		assert.Equal(t, "project_path:group/repo:ref_type:branch:ref:main", token.Subject)
	})
}

func TestExtractCircleCIOIDC_WithToken(t *testing.T) {
	clearCIPlatformEnv(t)

	claims := map[string]interface{}{
		"iss":                          "https://oidc.circleci.com/org/ORG_ID",
		"sub":                          "org/ORG_ID/project/PROJECT_ID/user/USER_ID",
		"aud":                          "sts.amazonaws.com",
		"oidc.circleci.com/project-id": "12345",
	}
	mockToken := createMockJWT(claims)

	withEnv(t, map[string]string{
		"CIRCLECI":          "true",
		"CIRCLE_OIDC_TOKEN": mockToken,
	}, func() {
		agent := New(DefaultConfig())
		token, err := agent.OIDC("")
		require.NoError(t, err)

		assert.Equal(t, models.PlatformCircleCI, token.Platform)
		assert.Equal(t, "CIRCLE_OIDC_TOKEN", token.TokenSource)
		assert.Equal(t, "sts.amazonaws.com", token.Audience)
		assert.Equal(t, "aws", token.DetectedProvider)
	})
}

func TestOIDCToken_Structure(t *testing.T) {
	token := OIDCToken{
		RawToken:         "eyJ...",
		Platform:         models.PlatformGitHubActions,
		TokenSource:      "ACTIONS_ID_TOKEN_REQUEST_URL",
		Issuer:           "https://token.actions.githubusercontent.com",
		Subject:          "repo:org/repo:ref:refs/heads/main",
		Audience:         "sts.amazonaws.com",
		ExpiresAt:        1735689600,
		IssuedAt:         1735686000,
		Repository:       "org/repo",
		RepositoryOwner:  "org",
		Workflow:         "CI",
		Actor:            "developer",
		Ref:              "refs/heads/main",
		RefType:          "branch",
		RunID:            "12345",
		Environment:      "production",
		JobWorkflowRef:   "org/repo/.github/workflows/ci.yml@refs/heads/main",
		DetectedProvider: "aws",
		TargetAudiences:  []string{"aws"},
		AllClaims:        map[string]interface{}{"iss": "https://token.actions.githubusercontent.com"},
	}

	// Verify all fields are set correctly
	assert.Equal(t, "eyJ...", token.RawToken)
	assert.Equal(t, models.PlatformGitHubActions, token.Platform)
	assert.Equal(t, "ACTIONS_ID_TOKEN_REQUEST_URL", token.TokenSource)
	assert.Equal(t, "https://token.actions.githubusercontent.com", token.Issuer)
	assert.Equal(t, "repo:org/repo:ref:refs/heads/main", token.Subject)
	assert.Equal(t, "sts.amazonaws.com", token.Audience)
	assert.Equal(t, int64(1735689600), token.ExpiresAt)
	assert.Equal(t, int64(1735686000), token.IssuedAt)
	assert.Equal(t, "org/repo", token.Repository)
	assert.Equal(t, "org", token.RepositoryOwner)
	assert.Equal(t, "CI", token.Workflow)
	assert.Equal(t, "developer", token.Actor)
	assert.Equal(t, "refs/heads/main", token.Ref)
	assert.Equal(t, "branch", token.RefType)
	assert.Equal(t, "12345", token.RunID)
	assert.Equal(t, "production", token.Environment)
	assert.Equal(t, "org/repo/.github/workflows/ci.yml@refs/heads/main", token.JobWorkflowRef)
	assert.Equal(t, "aws", token.DetectedProvider)
	assert.Len(t, token.TargetAudiences, 1)
	assert.NotNil(t, token.AllClaims)
}

func TestAudienceForProvider(t *testing.T) {
	tests := []struct {
		provider string
		args     []string
		expected string
	}{
		{"aws", nil, "sts.amazonaws.com"},
		{"gcp", []string{"--workload-identity-provider=projects/123/locations/global/pools/p/providers/gh"}, "//iam.googleapis.com/projects/123/locations/global/pools/p/providers/gh"},
		{"gcp", nil, "https://iam.googleapis.com"},
		{"azure", nil, "api://AzureADTokenExchange"},
		{"k8s", nil, "kubernetes"},
		{"unknown", nil, "sts.amazonaws.com"},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			assert.Equal(t, tt.expected, audienceForProvider(tt.provider, tt.args))
		})
	}
}

func TestExtractGitHubOIDC_PassesAudience(t *testing.T) {
	clearCIPlatformEnv(t)

	var capturedAudience string
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		capturedAudience = req.URL.Query().Get("audience")
		claims := map[string]interface{}{
			"iss": "https://token.actions.githubusercontent.com",
			"aud": capturedAudience,
		}
		return jsonResponse(http.StatusOK, `{"value":"`+createMockJWT(claims)+`"}`), nil
	})

	withEnv(t, map[string]string{
		"GITHUB_ACTIONS":                 "true",
		"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://mock.test/token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-token",
	}, func() {
		cfg := DefaultConfig()
		cfg.HTTPClient = mockClient
		agent := New(cfg)

		token, err := agent.extractGitHubOIDC("api://AzureADTokenExchange")
		require.NoError(t, err)
		assert.Equal(t, "api://AzureADTokenExchange", capturedAudience)
		assert.Equal(t, "api://AzureADTokenExchange", token.Audience)
	})
}

func TestPivotResult_Structure(t *testing.T) {
	result := models.PivotResult{
		Success:  true,
		Provider: "aws",
		Method:   "oidc",
		Credentials: map[string]string{
			"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
		},
		Resources: []models.CloudResource{
			{
				Type:   "s3_bucket",
				Name:   "my-bucket",
				Region: "us-east-1",
			},
		},
		Errors:   []string{},
		Duration: 150.5,
	}

	// Verify all fields
	assert.True(t, result.Success)
	assert.Equal(t, "aws", result.Provider)
	assert.Equal(t, "oidc", result.Method)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", result.Credentials["AWS_ACCESS_KEY_ID"])
	assert.Len(t, result.Resources, 1)
	assert.Equal(t, "s3_bucket", result.Resources[0].Type)
	assert.Empty(t, result.Errors)
	assert.Equal(t, 150.5, result.Duration)
}

func TestCloudResource_Structure(t *testing.T) {
	resource := models.CloudResource{
		Type:   "ecr_repository",
		ID:     "arn:aws:ecr:us-east-1:123456789:repository/my-repo",
		Name:   "my-repo",
		Region: "us-east-1",
		Metadata: map[string]string{
			"registryId": "123456789",
		},
	}

	// Verify all fields
	assert.Equal(t, "ecr_repository", resource.Type)
	assert.Equal(t, "arn:aws:ecr:us-east-1:123456789:repository/my-repo", resource.ID)
	assert.Equal(t, "my-repo", resource.Name)
	assert.Equal(t, "us-east-1", resource.Region)
	assert.Equal(t, "123456789", resource.Metadata["registryId"])
}

func TestPivotAWS_MissingRoleARN(t *testing.T) {
	clearCIPlatformEnv(t)

	// Unset AWS_ROLE_ARN
	os.Unsetenv("AWS_ROLE_ARN")
	os.Unsetenv("AWS_ROLE_TO_ASSUME")

	token := &OIDCToken{
		RepositoryOwner: "acme",
	}
	result := &models.PivotResult{
		Errors: []string{},
	}

	agent := New(DefaultConfig())
	err := agent.pivotAWS(token, result, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AWS_ROLE_ARN required")
	assert.Len(t, result.Errors, 1)
}

func TestPivotGCP_MissingConfig(t *testing.T) {
	clearCIPlatformEnv(t)

	// Unset GCP config
	os.Unsetenv("GCP_WORKLOAD_IDENTITY_PROVIDER")
	os.Unsetenv("GCP_SERVICE_ACCOUNT")

	token := &OIDCToken{}
	result := &models.PivotResult{
		Errors: []string{},
	}

	agent := New(DefaultConfig())
	err := agent.pivotGCP(token, result, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP_WORKLOAD_IDENTITY_PROVIDER and GCP_SERVICE_ACCOUNT required")
}

func TestPivotAzure_MissingConfig(t *testing.T) {
	clearCIPlatformEnv(t)

	// Unset Azure config
	os.Unsetenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_CLIENT_ID")

	token := &OIDCToken{}
	result := &models.PivotResult{
		Errors: []string{},
	}

	agent := New(DefaultConfig())
	err := agent.pivotAzure(token, result, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_TENANT_ID and AZURE_CLIENT_ID required")
}

func TestPivotKubernetes_MissingConfig(t *testing.T) {
	clearCIPlatformEnv(t)

	// Unset K8s config
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("K8S_SERVER")

	token := &OIDCToken{}
	result := &models.PivotResult{
		Errors: []string{},
	}

	agent := New(DefaultConfig())
	err := agent.pivotKubernetes(token, result)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kubernetes server not detected")
}

func TestOIDCPivot_AutoDetect_NoProvider(t *testing.T) {
	clearCIPlatformEnv(t)

	// Token with generic audience (no cloud provider detected)
	claims := map[string]interface{}{
		"iss": "https://example.com",
		"sub": "test",
		"aud": "generic-audience",
	}
	mockToken := createMockJWT(claims)

	withEnv(t, map[string]string{
		"GITLAB_CI":     "true",
		"CI_JOB_JWT_V2": mockToken,
	}, func() {
		agent := New(DefaultConfig())
		result, err := agent.OIDCPivot("auto", nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "auto-detection failed")
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})
}

func TestDecodeJWTClaims_PartialClaims(t *testing.T) {
	// Token with only some claims
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "subject",
	}

	jwt := createMockJWT(claims)
	token := &OIDCToken{RawToken: jwt}

	err := decodeJWTClaims(token)
	require.NoError(t, err)

	assert.Equal(t, "https://issuer.example.com", token.Issuer)
	assert.Equal(t, "subject", token.Subject)
	// Other fields should be empty/zero
	assert.Empty(t, token.Audience)
	assert.Zero(t, token.ExpiresAt)
	assert.Empty(t, token.Repository)
}

func TestGetArgOrEnv_ArgOverridesEnv(t *testing.T) {
	t.Setenv("AWS_ROLE_ARN", "env-role")
	args := []string{"--role-arn=arg-role"}
	result := getArgOrEnv(args, "role-arn", "AWS_ROLE_ARN")
	assert.Equal(t, "arg-role", result)
}

func TestGetArgOrEnv_FallbackToEnv(t *testing.T) {
	t.Setenv("AWS_ROLE_ARN", "env-role")
	result := getArgOrEnv(nil, "role-arn", "AWS_ROLE_ARN")
	assert.Equal(t, "env-role", result)
}

func TestGetArgOrEnv_FallbackChain(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("AWS_ROLE_ARN")
	t.Setenv("AWS_ROLE_TO_ASSUME", "fallback-role")
	result := getArgOrEnv(nil, "role-arn", "AWS_ROLE_ARN", "AWS_ROLE_TO_ASSUME")
	assert.Equal(t, "fallback-role", result)
}

func TestGetArgOrEnv_Empty(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("AWS_ROLE_ARN")
	result := getArgOrEnv(nil, "role-arn", "AWS_ROLE_ARN")
	assert.Empty(t, result)
}

func TestPivotAWS_ArgOverridesEnv(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("AWS_ROLE_ARN")
	os.Unsetenv("AWS_ROLE_TO_ASSUME")

	token := &OIDCToken{}
	result := &models.PivotResult{Errors: []string{}}
	agent := New(DefaultConfig())

	err := agent.pivotAWS(token, result, []string{"--role-arn=arn:aws:iam::999:role/test"})
	// Will fail at the aws CLI call, but should NOT fail with "AWS_ROLE_ARN required"
	if err != nil {
		assert.NotContains(t, err.Error(), "AWS_ROLE_ARN required")
	}
}
