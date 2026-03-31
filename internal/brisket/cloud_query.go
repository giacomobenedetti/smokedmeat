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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func (a *Agent) executeCloudQuery(ctx context.Context, args []string) *models.CloudQueryResult {
	if len(args) < 2 {
		return &models.CloudQueryResult{Error: "cloud-query requires [provider, query-type]"}
	}

	provider := args[0]
	queryType := args[1]

	if a.cloudCreds == nil {
		return &models.CloudQueryResult{
			Provider:  provider,
			QueryType: queryType,
			Error:     "no cloud credentials stored — run OIDC pivot first",
		}
	}

	result := &models.CloudQueryResult{
		Provider:  provider,
		QueryType: queryType,
	}

	switch provider {
	case "aws":
		a.queryAWS(ctx, result, queryType)
	case "gcp", "google":
		a.queryGCP(ctx, result, queryType)
	case "azure", "az":
		a.queryAzure(ctx, result, queryType)
	default:
		result.Error = fmt.Sprintf("unsupported provider for cloud-query: %s", provider)
	}

	return result
}

func (a *Agent) awsStaticCreds() credentials.StaticCredentialsProvider {
	return credentials.NewStaticCredentialsProvider(
		a.cloudCreds.AccessKeyID,
		a.cloudCreds.SecretKey,
		a.cloudCreds.SessionToken,
	)
}

func (a *Agent) awsRegion() string {
	if a.cloudCreds.Region != "" {
		return a.cloudCreds.Region
	}
	return "us-east-1"
}

func (a *Agent) queryAWS(ctx context.Context, result *models.CloudQueryResult, queryType string) {
	creds := a.awsStaticCreds()
	region := a.awsRegion()

	switch queryType {
	case "identity":
		stsClient := sts.New(sts.Options{Region: region, Credentials: creds, HTTPClient: a.client})
		identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			result.Error = fmt.Sprintf("sts:GetCallerIdentity failed: %v", err)
			return
		}
		result.Success = true
		result.Resources = []models.CloudResource{{
			Type: "identity",
			ID:   aws.ToString(identity.Arn),
			Name: aws.ToString(identity.UserId),
			Metadata: map[string]string{
				"Account": aws.ToString(identity.Account),
			},
		}}

	case "buckets":
		s3Client := s3.New(s3.Options{Region: region, Credentials: creds, HTTPClient: a.client})
		buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			result.Error = fmt.Sprintf("s3:ListBuckets failed: %v", err)
			return
		}
		result.Success = true
		for _, b := range buckets.Buckets {
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "s3_bucket",
				Name: aws.ToString(b.Name),
			})
		}

	case "ecr":
		ecrClient := ecr.New(ecr.Options{Region: region, Credentials: creds, HTTPClient: a.client})
		repos, err := ecrClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
		if err != nil {
			result.Error = fmt.Sprintf("ecr:DescribeRepositories failed: %v", err)
			return
		}
		result.Success = true
		for _, r := range repos.Repositories {
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "ecr_repository",
				ID:   aws.ToString(r.RepositoryArn),
				Name: aws.ToString(r.RepositoryName),
			})
		}

	default:
		result.Error = fmt.Sprintf("unknown AWS query type: %s (supported: identity, buckets, ecr)", queryType)
	}
}

func (a *Agent) gcpAuthedRequest(ctx context.Context, method, reqURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, reqURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cloudCreds.AccessToken)
	return a.client.Do(req)
}

func (a *Agent) queryGCP(ctx context.Context, result *models.CloudQueryResult, queryType string) {
	switch queryType {
	case "identity":
		project := a.cloudCreds.Project
		if project == "" {
			result.Error = "no GCP project stored from pivot"
			return
		}
		resp, err := a.gcpAuthedRequest(ctx, "GET",
			fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s", url.PathEscape(project)))
		if err != nil {
			result.Error = fmt.Sprintf("GCP project info failed: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			result.Error = explainGCPQueryFailure(queryType, project, resp.StatusCode, string(body))
			return
		}
		var proj struct {
			ProjectID     string `json:"projectId"`
			Name          string `json:"name"`
			ProjectNumber string `json:"projectNumber"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if json.Unmarshal(body, &proj) != nil {
			result.Error = "failed to parse GCP project response"
			return
		}
		result.Success = true
		result.Resources = []models.CloudResource{{
			Type: "project",
			ID:   proj.ProjectNumber,
			Name: proj.ProjectID,
			Metadata: map[string]string{
				"display_name": proj.Name,
			},
		}}

	case "buckets":
		project := a.cloudCreds.Project
		if project == "" {
			result.Error = "no GCP project stored from pivot"
			return
		}
		resp, err := a.gcpAuthedRequest(ctx, "GET",
			fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s", url.QueryEscape(project)))
		if err != nil {
			result.Error = fmt.Sprintf("GCS list buckets failed: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			result.Error = explainGCPQueryFailure(queryType, project, resp.StatusCode, string(body))
			return
		}
		var bucketList struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if json.Unmarshal(body, &bucketList) != nil {
			result.Error = "failed to parse GCS bucket list response"
			return
		}
		result.Success = true
		for _, b := range bucketList.Items {
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "gcs_bucket",
				Name: b.Name,
			})
		}

	case "projects":
		resp, err := a.gcpAuthedRequest(ctx, "GET",
			"https://cloudresourcemanager.googleapis.com/v1/projects")
		if err != nil {
			result.Error = fmt.Sprintf("GCP list projects failed: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			result.Error = explainGCPQueryFailure(queryType, "", resp.StatusCode, string(body))
			return
		}
		var projList struct {
			Projects []struct {
				ProjectID     string `json:"projectId"`
				Name          string `json:"name"`
				ProjectNumber string `json:"projectNumber"`
			} `json:"projects"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if json.Unmarshal(body, &projList) != nil {
			result.Error = "failed to parse GCP projects response"
			return
		}
		result.Success = true
		for _, p := range projList.Projects {
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "project",
				ID:   p.ProjectNumber,
				Name: p.ProjectID,
				Metadata: map[string]string{
					"display_name": p.Name,
				},
			})
		}

	default:
		result.Error = fmt.Sprintf("unknown GCP query type: %s (supported: identity, buckets, projects)", queryType)
	}
}

func explainGCPQueryFailure(queryType, project string, statusCode int, body string) string {
	body = strings.Join(strings.Fields(body), " ")
	if statusCode == http.StatusForbidden {
		switch queryType {
		case "identity":
			return fmt.Sprintf("missing resourcemanager.projects.get on project %s (403). Quick checks are permission-sensitive; 'cloud shell' may still work with the stored token and project.", project)
		case "projects":
			return "missing resourcemanager.projects.list (403). Quick checks are permission-sensitive; 'cloud shell' may still work with the stored token and known project."
		case "buckets":
			return fmt.Sprintf("missing storage.buckets.list on project %s (403). Listing a known bucket path in 'cloud shell' may still work.", project)
		}
	}

	switch queryType {
	case "identity":
		return fmt.Sprintf("GCP project info returned %d: %s", statusCode, body)
	case "projects":
		return fmt.Sprintf("GCP list projects returned %d: %s", statusCode, body)
	case "buckets":
		return fmt.Sprintf("GCS list buckets returned %d: %s", statusCode, body)
	default:
		return fmt.Sprintf("GCP query %s returned %d: %s", queryType, statusCode, body)
	}
}

func (a *Agent) azureCredential() (azcore.TokenCredential, error) {
	if a.cloudCreds.RawToken != "" && a.cloudCreds.TenantID != "" && a.cloudCreds.ClientID != "" {
		return azidentity.NewClientAssertionCredential(
			a.cloudCreds.TenantID, a.cloudCreds.ClientID,
			func(_ context.Context) (string, error) { return a.cloudCreds.RawToken, nil },
			nil,
		)
	}

	if a.cloudCreds.AccessToken != "" {
		return newStaticAzureToken(a.cloudCreds.AccessToken), nil
	}

	return nil, fmt.Errorf("no usable Azure credentials stored")
}

func (a *Agent) queryAzure(ctx context.Context, result *models.CloudQueryResult, queryType string) {
	cred, err := a.azureCredential()
	if err != nil {
		result.Error = err.Error()
		return
	}

	opts := &arm.ClientOptions{}

	switch queryType {
	case "identity":
		subClient, err := armsubscriptions.NewClient(cred, nil)
		if err != nil {
			result.Error = fmt.Sprintf("azure subscriptions client failed: %v", err)
			return
		}
		pager := subClient.NewListPager(nil)
		page, err := pager.NextPage(ctx)
		if err != nil {
			result.Error = fmt.Sprintf("azure list subscriptions failed: %v", err)
			return
		}
		result.Success = true
		for _, sub := range page.Value {
			state := ""
			if sub.State != nil {
				state = string(*sub.State)
			}
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "subscription",
				ID:   aws.ToString(sub.SubscriptionID),
				Name: aws.ToString(sub.DisplayName),
				Metadata: map[string]string{
					"state": state,
				},
			})
		}

	case "storage":
		subID := a.cloudCreds.SubscriptionID
		if subID == "" {
			result.Error = "no Azure subscription ID stored from pivot"
			return
		}
		stClient, err := armstorage.NewAccountsClient(subID, cred, opts)
		if err != nil {
			result.Error = fmt.Sprintf("azure storage client failed: %v", err)
			return
		}
		pager := stClient.NewListPager(nil)
		page, err := pager.NextPage(ctx)
		if err != nil {
			result.Error = fmt.Sprintf("azure list storage accounts failed: %v", err)
			return
		}
		result.Success = true
		for _, acct := range page.Value {
			result.Resources = append(result.Resources, models.CloudResource{
				Type:   "storage_account",
				ID:     aws.ToString(acct.ID),
				Name:   aws.ToString(acct.Name),
				Region: aws.ToString(acct.Location),
			})
		}

	case "resource-groups":
		subID := a.cloudCreds.SubscriptionID
		if subID == "" {
			result.Error = "no Azure subscription ID stored from pivot"
			return
		}
		rgClient, err := armresources.NewResourceGroupsClient(subID, cred, opts)
		if err != nil {
			result.Error = fmt.Sprintf("azure resource groups client failed: %v", err)
			return
		}
		pager := rgClient.NewListPager(nil)
		page, err := pager.NextPage(ctx)
		if err != nil {
			result.Error = fmt.Sprintf("azure list resource groups failed: %v", err)
			return
		}
		result.Success = true
		for _, g := range page.Value {
			result.Resources = append(result.Resources, models.CloudResource{
				Type:   "resource_group",
				ID:     aws.ToString(g.ID),
				Name:   aws.ToString(g.Name),
				Region: aws.ToString(g.Location),
			})
		}

	case "acr":
		subID := a.cloudCreds.SubscriptionID
		if subID == "" {
			result.Error = "no Azure subscription ID stored from pivot"
			return
		}
		acrClient, err := armcontainerregistry.NewRegistriesClient(subID, cred, opts)
		if err != nil {
			result.Error = fmt.Sprintf("azure acr client failed: %v", err)
			return
		}
		pager := acrClient.NewListPager(nil)
		page, err := pager.NextPage(ctx)
		if err != nil {
			result.Error = fmt.Sprintf("azure list container registries failed: %v", err)
			return
		}
		result.Success = true
		for _, reg := range page.Value {
			loginServer := ""
			if reg.Properties != nil && reg.Properties.LoginServer != nil {
				loginServer = *reg.Properties.LoginServer
			}
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "container_registry",
				ID:   aws.ToString(reg.ID),
				Name: aws.ToString(reg.Name),
				Metadata: map[string]string{
					"loginServer": loginServer,
				},
			})
		}

	default:
		result.Error = fmt.Sprintf("unknown Azure query type: %s (supported: identity, storage, resource-groups, acr)", queryType)
	}
}

type staticAzureToken struct {
	token string
}

func newStaticAzureToken(token string) *staticAzureToken {
	return &staticAzureToken{token: token}
}

func (s *staticAzureToken) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: s.token}, nil
}
