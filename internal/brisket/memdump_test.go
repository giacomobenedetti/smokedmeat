// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func TestDumpRunnerSecrets_NoProcess(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.DumpRunnerSecrets()

	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Error)
	assert.Empty(t, result.Secrets)
}

func TestCollectMemDumpResults_IncludesTokenPermissions(t *testing.T) {
	results := make(chan gump.Result, 4)
	results <- gump.Result{Type: gump.ResultSecret, Raw: `"GITHUB_TOKEN"{"value":"ghs_abc","isSecret":true}`}
	results <- gump.Result{Type: gump.ResultTokenPermissions, Raw: `"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}`}
	results <- gump.Result{Type: gump.ResultVar, Raw: `"GCP_PROJECT_ID"{"value":"demo-project","isSecret":false}`}
	results <- gump.Result{Type: gump.ResultEndpoint, Raw: `"AccessToken":"runtime-token"`, Endpoint: gump.Endpoint{InternalKey: "AccessToken", EnvName: "ACTIONS_RUNTIME_TOKEN", Value: "runtime-token"}}
	close(results)

	secrets, vars, endpoints := collectMemDumpResults(results)

	assert.ElementsMatch(t, []string{
		`"GITHUB_TOKEN"{"value":"ghs_abc","isSecret":true}`,
		`"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}`,
	}, secrets)
	assert.ElementsMatch(t, []string{
		`"GCP_PROJECT_ID"{"value":"demo-project","isSecret":false}`,
	}, vars)
	assert.Equal(t, []gump.Endpoint{
		{InternalKey: "AccessToken", EnvName: "ACTIONS_RUNTIME_TOKEN", Value: "runtime-token"},
	}, endpoints)
}

func TestCollectMemDumpResults_PreservesDistinctEndpointCandidates(t *testing.T) {
	results := make(chan gump.Result, 4)
	results <- gump.Result{
		Type: gump.ResultEndpoint,
		Raw:  `"AccessToken":"short-token"`,
		Endpoint: gump.Endpoint{
			InternalKey: "AccessToken",
			EnvName:     "ACTIONS_RUNTIME_TOKEN",
			Value:       "short-token",
		},
	}
	results <- gump.Result{
		Type: gump.ResultEndpoint,
		Raw:  `"AccessToken":"long-token"`,
		Endpoint: gump.Endpoint{
			InternalKey: "AccessToken",
			EnvName:     "ACTIONS_RUNTIME_TOKEN",
			Value:       "long-token",
		},
	}
	close(results)

	_, _, endpoints := collectMemDumpResults(results)

	assert.Equal(t, []gump.Endpoint{
		{InternalKey: "AccessToken", EnvName: "ACTIONS_RUNTIME_TOKEN", Value: "long-token"},
		{InternalKey: "AccessToken", EnvName: "ACTIONS_RUNTIME_TOKEN", Value: "short-token"},
	}, endpoints)
}
