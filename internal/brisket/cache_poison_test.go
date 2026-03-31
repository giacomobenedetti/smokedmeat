// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func TestResolveCachePoisonRuntime_NormalizesMemDumpEndpointValues(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "")
	t.Setenv("ACTIONS_RESULTS_URL", "")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	runtimeToken := strings.Repeat("t", 2199)
	corruptedToken := runtimeToken[:800] + "\r\n\t" + runtimeToken[800:1600] + "\n" + runtimeToken[1600:]

	agent := New(DefaultConfig())
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return &MemDumpResult{
			Endpoints: []gump.Endpoint{
				{EnvName: "ACTIONS_RUNTIME_TOKEN", Value: corruptedToken},
				{EnvName: "ACTIONS_RESULTS_URL", Value: `https:\/\/results.actions.example\/_apis\/results\/123` + "\r\n"},
				{EnvName: "ACTIONS_CACHE_URL", Value: `https:\/\/artifactcache.actions.example\/_apis\/artifactcache` + "\n"},
			},
			Vars: []string{
				`{"k":"ACTIONS_CACHE_SERVICE_V2","v":"true\r"}`,
			},
		}
	}

	runtimeEnv, source, err := agent.resolveCachePoisonRuntime()
	require.NoError(t, err)
	assert.Equal(t, "memdump", source)
	assert.Equal(t, runtimeToken, runtimeEnv.RuntimeToken)
	assert.NotContains(t, runtimeEnv.RuntimeToken, "\r")
	assert.NotContains(t, runtimeEnv.RuntimeToken, "\n")
	assert.Equal(t, "https://results.actions.example/_apis/results/123", runtimeEnv.ResultsURL)
	assert.Equal(t, "https://artifactcache.actions.example/_apis/artifactcache", runtimeEnv.CacheURL)
	assert.True(t, runtimeEnv.CacheServiceV2)
}

func TestResolveCachePoisonRuntime_DefaultsToV2(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "")
	t.Setenv("ACTIONS_RESULTS_URL", "")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	runtimeToken := strings.Repeat("t", 2199)

	agent := New(DefaultConfig())
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return &MemDumpResult{
			Endpoints: []gump.Endpoint{
				{EnvName: "ACTIONS_RUNTIME_TOKEN", Value: runtimeToken},
				{EnvName: "ACTIONS_RESULTS_URL", Value: "https://results.actions.githubusercontent.com/example/"},
				{EnvName: "ACTIONS_CACHE_URL", Value: "https://artifactcache.actions.githubusercontent.com/example/"},
			},
		}
	}

	runtimeEnv, source, err := agent.resolveCachePoisonRuntime()
	require.NoError(t, err)
	assert.Equal(t, "memdump", source)
	assert.Equal(t, runtimeToken, runtimeEnv.RuntimeToken)
	assert.True(t, runtimeEnv.CacheServiceV2)
}

func TestResolveCachePoisonRuntime_PrefersLongestMemDumpEndpointToken(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "")
	t.Setenv("ACTIONS_RESULTS_URL", "")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	longToken := strings.Repeat("t", 2199)

	agent := New(DefaultConfig())
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return &MemDumpResult{
			Endpoints: []gump.Endpoint{
				{EnvName: "ACTIONS_RUNTIME_TOKEN", Value: "bad"},
				{EnvName: "ACTIONS_RESULTS_URL", Value: "https://results.actions.githubusercontent.com/example/"},
				{EnvName: "ACTIONS_CACHE_URL", Value: "https://artifactcache.actions.githubusercontent.com/example/"},
				{EnvName: "ACTIONS_RUNTIME_TOKEN", Value: longToken},
			},
		}
	}

	runtimeEnv, source, err := agent.resolveCachePoisonRuntime()
	require.NoError(t, err)
	assert.Equal(t, "memdump", source)
	assert.Equal(t, longToken, runtimeEnv.RuntimeToken)
	assert.True(t, runtimeEnv.CacheServiceV2)
}
