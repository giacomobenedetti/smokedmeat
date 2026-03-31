// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestPivotAzure_MissingTenantID(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_CLIENT_ID")

	token := &OIDCToken{}
	result := &models.PivotResult{Errors: []string{}}

	agent := New(DefaultConfig())
	err := agent.pivotAzure(token, result, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_TENANT_ID and AZURE_CLIENT_ID required")
}

func TestPivotAzure_MissingClientID(t *testing.T) {
	clearCIPlatformEnv(t)
	t.Setenv("AZURE_TENANT_ID", "test-tenant")
	os.Unsetenv("AZURE_CLIENT_ID")

	token := &OIDCToken{}
	result := &models.PivotResult{Errors: []string{}}

	agent := New(DefaultConfig())
	err := agent.pivotAzure(token, result, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_TENANT_ID and AZURE_CLIENT_ID required")
}

func TestPivotAzure_ArgOverridesEnv(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_CLIENT_ID")

	token := &OIDCToken{RawToken: createMockJWT(map[string]interface{}{"iss": "test"})}
	result := &models.PivotResult{Errors: []string{}}
	agent := New(DefaultConfig())

	err := agent.pivotAzure(token, result, []string{"--tenant-id=t1", "--client-id=c1"})
	if err != nil {
		assert.NotContains(t, err.Error(), "AZURE_TENANT_ID and AZURE_CLIENT_ID required")
	}
}
