// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestPivotAWS_Success(t *testing.T) {
	clearCIPlatformEnv(t)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789:role/test-role")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")

	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		body := req.URL.String()

		if strings.Contains(body, "AssumeRoleWithWebIdentity") || req.URL.Host == "sts.us-west-2.amazonaws.com" {
			return xmlResponse(http.StatusOK, `<AssumeRoleWithWebIdentityResponse>
				<AssumeRoleWithWebIdentityResult>
					<Credentials>
						<AccessKeyId>AKIATEST123</AccessKeyId>
						<SecretAccessKey>secret-test-key</SecretAccessKey>
						<SessionToken>session-test-token</SessionToken>
						<Expiration>2026-03-01T00:00:00Z</Expiration>
					</Credentials>
					<AssumedRoleUser>
						<Arn>arn:aws:sts::123456789:assumed-role/test-role/smokedmeat</Arn>
						<AssumedRoleId>AROA:smokedmeat</AssumedRoleId>
					</AssumedRoleUser>
				</AssumeRoleWithWebIdentityResult>
			</AssumeRoleWithWebIdentityResponse>`), nil
		}

		if strings.Contains(body, "GetCallerIdentity") {
			return xmlResponse(http.StatusOK, `<GetCallerIdentityResponse>
				<GetCallerIdentityResult>
					<Account>123456789</Account>
					<Arn>arn:aws:sts::123456789:assumed-role/test-role/smokedmeat</Arn>
					<UserId>AROA:smokedmeat</UserId>
				</GetCallerIdentityResult>
			</GetCallerIdentityResponse>`), nil
		}

		if strings.Contains(body, "ListBuckets") || (req.URL.Host == "s3.us-west-2.amazonaws.com" && req.Method == "GET") {
			return xmlResponse(http.StatusOK, `<ListAllMyBucketsResult>
				<Buckets>
					<Bucket><Name>test-bucket-1</Name></Bucket>
					<Bucket><Name>test-bucket-2</Name></Bucket>
				</Buckets>
			</ListAllMyBucketsResult>`), nil
		}

		if strings.Contains(body, "DescribeRepositories") || strings.Contains(req.URL.Host, "ecr") {
			return jsonResponse(http.StatusOK, `{"repositories":[{"repositoryArn":"arn:aws:ecr:us-west-2:123456789:repository/my-app","repositoryName":"my-app"}]}`), nil
		}

		return emptyResponse(http.StatusOK), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)

	token := &OIDCToken{RawToken: createMockJWT(map[string]interface{}{"iss": "test", "aud": "sts.amazonaws.com"})}
	result := &models.PivotResult{Errors: []string{}}

	err := agent.pivotAWS(token, result, nil)
	require.NoError(t, err)

	assert.Equal(t, "AKIATEST123", result.RawCredentials["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, "secret-test-key", result.RawCredentials["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, "session-test-token", result.RawCredentials["AWS_SESSION_TOKEN"])
	assert.Equal(t, "us-west-2", result.RawCredentials["AWS_DEFAULT_REGION"])
	assert.Contains(t, result.Credentials["AWS_SECRET_ACCESS_KEY"], "•••")

	assert.Equal(t, "AKIATEST123", os.Getenv("AWS_ACCESS_KEY_ID"))
}

func TestPivotAWS_STSError(t *testing.T) {
	clearCIPlatformEnv(t)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789:role/bad-role")

	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		return xmlResponse(http.StatusForbidden, `<ErrorResponse>
			<Error>
				<Code>AccessDenied</Code>
				<Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message>
			</Error>
		</ErrorResponse>`), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)

	token := &OIDCToken{RawToken: createMockJWT(map[string]interface{}{"iss": "test"})}
	result := &models.PivotResult{Errors: []string{}}

	err := agent.pivotAWS(token, result, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AssumeRoleWithWebIdentity")
}

func TestPivotAWS_DurationSecondsArg(t *testing.T) {
	clearCIPlatformEnv(t)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789:role/test")

	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		return xmlResponse(http.StatusOK, `<AssumeRoleWithWebIdentityResponse>
			<AssumeRoleWithWebIdentityResult>
				<Credentials>
					<AccessKeyId>AKIA</AccessKeyId>
					<SecretAccessKey>secret</SecretAccessKey>
					<SessionToken>token</SessionToken>
					<Expiration>2026-03-01T00:00:00Z</Expiration>
				</Credentials>
				<AssumedRoleUser>
					<Arn>arn:aws:sts::123:assumed-role/test/s</Arn>
				</AssumedRoleUser>
			</AssumeRoleWithWebIdentityResult>
		</AssumeRoleWithWebIdentityResponse>`), nil
	})

	cfg := DefaultConfig()
	cfg.HTTPClient = mockClient
	agent := New(cfg)

	token := &OIDCToken{RawToken: createMockJWT(map[string]interface{}{"iss": "test"})}
	result := &models.PivotResult{Errors: []string{}}

	err := agent.pivotAWS(token, result, []string{"--role-duration-seconds=7200"})
	require.NoError(t, err)
	assert.NotEmpty(t, result.RawCredentials["AWS_ACCESS_KEY_ID"])
}

func TestExtractProjectFromSA(t *testing.T) {
	tests := []struct {
		sa      string
		project string
	}{
		{"deploy@my-project.iam.gserviceaccount.com", "my-project"},
		{"sa@nested-proj-123.iam.gserviceaccount.com", "nested-proj-123"},
		{"nodomain@gmail.com", ""},
		{"noat", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.sa, func(t *testing.T) {
			assert.Equal(t, tt.project, extractProjectFromSA(tt.sa))
		})
	}
}

func TestParseLifetimeSeconds(t *testing.T) {
	assert.Equal(t, 3600, parseLifetimeSeconds("3600"))
	assert.Equal(t, 0, parseLifetimeSeconds("invalid"))
	assert.Equal(t, 0, parseLifetimeSeconds("-1"))
	assert.Equal(t, 0, parseLifetimeSeconds(""))
}
