// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestPivotGCP_MissingWorkloadProvider(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("GCP_WORKLOAD_IDENTITY_PROVIDER")
	os.Unsetenv("GCP_SERVICE_ACCOUNT")

	token := &OIDCToken{}
	result := &models.PivotResult{Errors: []string{}}

	agent := New(DefaultConfig())
	err := agent.pivotGCP(token, result, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP_WORKLOAD_IDENTITY_PROVIDER and GCP_SERVICE_ACCOUNT required")
}

func TestPivotGCP_ArgOverridesEnv(t *testing.T) {
	clearCIPlatformEnv(t)
	os.Unsetenv("GCP_WORKLOAD_IDENTITY_PROVIDER")
	os.Unsetenv("GCP_SERVICE_ACCOUNT")

	token := &OIDCToken{RawToken: createMockJWT(map[string]interface{}{"iss": "test", "aud": "test"})}
	result := &models.PivotResult{Errors: []string{}}
	agent := New(DefaultConfig())

	err := agent.pivotGCP(token, result, []string{
		"--workload-identity-provider=projects/123/locations/global/workloadIdentityPools/pool/providers/gh",
		"--service-account=sa@proj.iam.gserviceaccount.com",
	})
	if err != nil {
		assert.NotContains(t, err.Error(), "GCP_WORKLOAD_IDENTITY_PROVIDER and GCP_SERVICE_ACCOUNT required")
	}
}
