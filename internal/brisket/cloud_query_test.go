// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestCloudQuery_NoCreds(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.executeCloudQuery(context.Background(), []string{"aws", "buckets"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no cloud credentials stored")
}

func TestCloudQuery_MissingArgs(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.executeCloudQuery(context.Background(), []string{"aws"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "cloud-query requires")
}

func TestCloudQuery_UnsupportedProvider(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{Provider: "nope"}
	result := agent.executeCloudQuery(context.Background(), []string{"nope", "buckets"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "unsupported provider")
}

func TestCloudQuery_AWS_Identity(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "GetCallerIdentity") || req.URL.Host == "sts.us-west-2.amazonaws.com" {
			return xmlResponse(http.StatusOK, `<GetCallerIdentityResponse>
				<GetCallerIdentityResult>
					<Account>123456789</Account>
					<Arn>arn:aws:sts::123456789:assumed-role/test/smokedmeat</Arn>
					<UserId>AROA:smokedmeat</UserId>
				</GetCallerIdentityResult>
			</GetCallerIdentityResponse>`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:     "aws",
		AccessKeyID:  "AKIATEST",
		SecretKey:    "secret",
		SessionToken: "token",
		Region:       "us-west-2",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"aws", "identity"})
	require.True(t, result.Success)
	assert.Equal(t, "aws", result.Provider)
	assert.Equal(t, "identity", result.QueryType)
	require.Len(t, result.Resources, 1)
	assert.Equal(t, "identity", result.Resources[0].Type)
	assert.Contains(t, result.Resources[0].ID, "arn:aws:sts")
	assert.Equal(t, "123456789", result.Resources[0].Metadata["Account"])
}

func TestCloudQuery_AWS_Buckets(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "s3.us-east-1.amazonaws.com" || strings.Contains(req.URL.String(), "ListBuckets") {
			return xmlResponse(http.StatusOK, `<ListAllMyBucketsResult>
				<Buckets>
					<Bucket><Name>bucket-alpha</Name></Bucket>
					<Bucket><Name>bucket-beta</Name></Bucket>
					<Bucket><Name>bucket-gamma</Name></Bucket>
				</Buckets>
			</ListAllMyBucketsResult>`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:     "aws",
		AccessKeyID:  "AKIATEST",
		SecretKey:    "secret",
		SessionToken: "token",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"aws", "buckets"})
	require.True(t, result.Success)
	assert.Len(t, result.Resources, 3)
	assert.Equal(t, "s3_bucket", result.Resources[0].Type)
	assert.Equal(t, "bucket-alpha", result.Resources[0].Name)
}

func TestCloudQuery_AWS_ECR(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "ecr") || strings.Contains(req.URL.String(), "DescribeRepositories") {
			return jsonResponse(http.StatusOK, `{"repositories":[
				{"repositoryArn":"arn:aws:ecr:us-east-1:123:repository/app","repositoryName":"app"},
				{"repositoryArn":"arn:aws:ecr:us-east-1:123:repository/web","repositoryName":"web"}
			]}`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:     "aws",
		AccessKeyID:  "AKIATEST",
		SecretKey:    "secret",
		SessionToken: "token",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"aws", "ecr"})
	require.True(t, result.Success)
	assert.Len(t, result.Resources, 2)
	assert.Equal(t, "ecr_repository", result.Resources[0].Type)
	assert.Equal(t, "app", result.Resources[0].Name)
}

func TestCloudQuery_AWS_UnknownQueryType(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{Provider: "aws"}
	result := agent.executeCloudQuery(context.Background(), []string{"aws", "rds"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "unknown AWS query type")
}

func TestCloudQuery_GCP_Buckets(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "storage.googleapis.com") {
			return jsonResponse(http.StatusOK, `{"items":[
				{"name":"my-bucket-1"},
				{"name":"my-bucket-2"}
			]}`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:    "gcp",
		AccessToken: "ya29.test-token",
		Project:     "my-project",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "buckets"})
	require.True(t, result.Success)
	assert.Len(t, result.Resources, 2)
	assert.Equal(t, "gcs_bucket", result.Resources[0].Type)
	assert.Equal(t, "my-bucket-1", result.Resources[0].Name)
}

func TestCloudQuery_GCP_Identity(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "cloudresourcemanager") {
			return jsonResponse(http.StatusOK, `{
				"projectId": "my-project",
				"name": "My Project",
				"projectNumber": "123456789"
			}`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:    "gcp",
		AccessToken: "ya29.test-token",
		Project:     "my-project",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "identity"})
	require.True(t, result.Success)
	require.Len(t, result.Resources, 1)
	assert.Equal(t, "project", result.Resources[0].Type)
	assert.Equal(t, "my-project", result.Resources[0].Name)
	assert.Equal(t, "123456789", result.Resources[0].ID)
}

func TestCloudQuery_GCP_Projects(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "cloudresourcemanager") {
			return jsonResponse(http.StatusOK, `{"projects":[
				{"projectId":"proj-a","name":"Project A","projectNumber":"111"},
				{"projectId":"proj-b","name":"Project B","projectNumber":"222"}
			]}`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:    "gcp",
		AccessToken: "ya29.test-token",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "projects"})
	require.True(t, result.Success)
	assert.Len(t, result.Resources, 2)
	assert.Equal(t, "proj-a", result.Resources[0].Name)
}

func TestCloudQuery_GCP_IdentityPermissionDenied(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "cloudresourcemanager") {
			return jsonResponse(http.StatusForbidden, `{"error":{"code":403,"message":"permission denied"}}`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:    "gcp",
		AccessToken: "ya29.test-token",
		Project:     "my-project",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "identity"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "missing resourcemanager.projects.get")
	assert.Contains(t, result.Error, "cloud shell")
}

func TestCloudQuery_GCP_ProjectsPermissionDenied(t *testing.T) {
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "cloudresourcemanager") {
			return jsonResponse(http.StatusForbidden, `{"error":{"code":403,"message":"permission denied"}}`), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)
	agent.cloudCreds = &CloudCredentials{
		Provider:    "gcp",
		AccessToken: "ya29.test-token",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "projects"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "missing resourcemanager.projects.list")
	assert.Contains(t, result.Error, "cloud shell")
}

func TestCloudQuery_GCP_NoProject(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{
		Provider:    "gcp",
		AccessToken: "ya29.test-token",
	}

	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "buckets"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no GCP project")
}

func TestCloudQuery_GCP_UnknownQueryType(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{Provider: "gcp", AccessToken: "ya29.test"}
	result := agent.executeCloudQuery(context.Background(), []string{"gcp", "compute"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "unknown GCP query type")
}

func TestCloudQuery_Azure_NoCredentials(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{Provider: "azure"}
	result := agent.executeCloudQuery(context.Background(), []string{"azure", "identity"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no usable Azure credentials")
}

func TestCloudQuery_Azure_StorageNoSubscription(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{
		Provider:    "azure",
		AccessToken: "eyJ0test",
	}
	result := agent.executeCloudQuery(context.Background(), []string{"azure", "storage"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no Azure subscription ID")
}

func TestCloudQuery_Azure_UnknownQueryType(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{
		Provider:    "azure",
		AccessToken: "eyJ0test",
	}
	result := agent.executeCloudQuery(context.Background(), []string{"azure", "vms"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "unknown Azure query type")
}

func TestStoreCloudCreds_AWS(t *testing.T) {
	agent := New(DefaultConfig())
	agent.storeCloudCreds(pivotResultFixture("aws", map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIATEST",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "token",
		"AWS_DEFAULT_REGION":    "us-west-2",
	}))

	require.NotNil(t, agent.cloudCreds)
	assert.Equal(t, "aws", agent.cloudCreds.Provider)
	assert.Equal(t, "AKIATEST", agent.cloudCreds.AccessKeyID)
	assert.Equal(t, "secret", agent.cloudCreds.SecretKey)
	assert.Equal(t, "token", agent.cloudCreds.SessionToken)
	assert.Equal(t, "us-west-2", agent.cloudCreds.Region)
}

func TestStoreCloudCreds_GCP(t *testing.T) {
	agent := New(DefaultConfig())
	agent.storeCloudCreds(pivotResultFixture("gcp", map[string]string{
		"ACCESS_TOKEN": "ya29.test",
		"PROJECT":      "my-project",
	}))

	require.NotNil(t, agent.cloudCreds)
	assert.Equal(t, "gcp", agent.cloudCreds.Provider)
	assert.Equal(t, "ya29.test", agent.cloudCreds.AccessToken)
	assert.Equal(t, "my-project", agent.cloudCreds.Project)
}

func TestStoreCloudCreds_Azure(t *testing.T) {
	agent := New(DefaultConfig())
	agent.lastOIDC = &OIDCToken{RawToken: "eyJ0.test.jwt"}
	agent.storeCloudCreds(pivotResultFixture("azure", map[string]string{
		"ACCESS_TOKEN":    "eyJ0az",
		"TENANT_ID":       "t1",
		"CLIENT_ID":       "c1",
		"SUBSCRIPTION_ID": "sub1",
	}))

	require.NotNil(t, agent.cloudCreds)
	assert.Equal(t, "azure", agent.cloudCreds.Provider)
	assert.Equal(t, "eyJ0az", agent.cloudCreds.AccessToken)
	assert.Equal(t, "t1", agent.cloudCreds.TenantID)
	assert.Equal(t, "c1", agent.cloudCreds.ClientID)
	assert.Equal(t, "sub1", agent.cloudCreds.SubscriptionID)
	assert.Equal(t, "eyJ0.test.jwt", agent.cloudCreds.RawToken)
}

func TestStoreCloudCreds_NilResult(t *testing.T) {
	agent := New(DefaultConfig())
	agent.storeCloudCreds(nil)
	assert.Nil(t, agent.cloudCreds)
}

func TestStoreCloudCreds_FailedPivot(t *testing.T) {
	agent := New(DefaultConfig())
	result := pivotResultFixture("aws", map[string]string{"AWS_ACCESS_KEY_ID": "test"})
	result.Success = false
	agent.storeCloudCreds(result)
	assert.Nil(t, agent.cloudCreds)
}

func TestCloudQuery_DefaultRegion(t *testing.T) {
	agent := New(DefaultConfig())
	agent.cloudCreds = &CloudCredentials{Provider: "aws"}
	assert.Equal(t, "us-east-1", agent.awsRegion())

	agent.cloudCreds.Region = "eu-west-1"
	assert.Equal(t, "eu-west-1", agent.awsRegion())
}

func pivotResultFixture(provider string, rawCreds map[string]string) *models.PivotResult {
	return &models.PivotResult{
		Success:        true,
		Provider:       provider,
		Method:         "oidc",
		RawCredentials: rawCreds,
	}
}
