// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build gumpacceptance
// +build gumpacceptance

package brisket

import (
	"strings"
	"testing"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func TestResolveCachePoisonRuntime_FromGumpScannedRuntimeTuple(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "")
	t.Setenv("ACTIONS_RESULTS_URL", "")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	runtimeToken := strings.Repeat("r", 2199)
	data := []byte(
		`"ACTIONS_RUNTIME_TOKEN"{"value":"` + runtimeToken + `","isSecret":true}` +
			`{"vars":{"d":[` +
			`{"k":"ACTIONS_RESULTS_URL","v":"https://results.actions.example/_apis/results"},` +
			`{"k":"ACTIONS_CACHE_URL","v":"https://cache.actions.example/_apis/artifactcache"},` +
			`{"k":"ACTIONS_CACHE_SERVICE_V2","v":"true"}` +
			`]}}`,
	)

	memDump := memDumpResultFromChunk(data)

	agent := New(DefaultConfig())
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return memDump
	}

	runtimeEnv, source, err := agent.resolveCachePoisonRuntime()
	if err != nil {
		t.Fatalf("expected runtime tuple from memdump, got %v", err)
	}
	if source != "memdump" {
		t.Fatalf("expected memdump source, got %q", source)
	}

	want := cachepoison.RuntimeEnvironment{
		RuntimeToken:   runtimeToken,
		ResultsURL:     "https://results.actions.example/_apis/results",
		CacheURL:       "https://cache.actions.example/_apis/artifactcache",
		CacheServiceV2: true,
	}
	if runtimeEnv != want {
		t.Fatalf("unexpected runtime env: %#v", runtimeEnv)
	}
}

func TestResolveCachePoisonRuntime_FromGumpEndpointResults(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "")
	t.Setenv("ACTIONS_RESULTS_URL", "")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	runtimeToken := strings.Repeat("e", 2199)
	data := []byte(
		`{"authorization":{"parameters":{"AccessToken":"` + runtimeToken + `"}},` +
			`"data":{"CacheServerUrl":"https://cache.actions.example/_apis/artifactcache",` +
			`"ResultsServiceUrl":"https://results.actions.example/_apis/results"}}`,
	)

	memDump := memDumpResultFromChunk(data)
	memDump.Endpoints = append(memDump.Endpoints, gump.Endpoint{
		InternalKey: "CacheServiceVersion",
		EnvName:     "ACTIONS_CACHE_SERVICE_V2",
		Value:       "true",
	})

	agent := New(DefaultConfig())
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return memDump
	}

	runtimeEnv, source, err := agent.resolveCachePoisonRuntime()
	if err != nil {
		t.Fatalf("expected runtime tuple from endpoint results, got %v", err)
	}
	if source != "memdump" {
		t.Fatalf("expected memdump source, got %q", source)
	}

	want := cachepoison.RuntimeEnvironment{
		RuntimeToken:   runtimeToken,
		ResultsURL:     "https://results.actions.example/_apis/results",
		CacheURL:       "https://cache.actions.example/_apis/artifactcache",
		CacheServiceV2: true,
	}
	if runtimeEnv != want {
		t.Fatalf("unexpected runtime env: %#v", runtimeEnv)
	}
}

func TestResolveCachePoisonRuntime_PrefersRuntimeTokenBoundToResultsContext(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "")
	t.Setenv("ACTIONS_RESULTS_URL", "")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	runtimeToken := strings.Repeat("e", 2199)
	falsePositive := strings.Repeat("f", 279)
	data := []byte(
		`{"name":"SystemVssConnection","authorization":{"parameters":{"AccessToken":"` + runtimeToken + `"},"scheme":"OAuth"},"data":{"CacheServerUrl":"https://cache.actions.example/_apis/artifactcache","ResultsServiceUrl":"https://results.actions.example/_apis/results"}}` +
			`{"name":"UnrelatedConnection","authorization":{"parameters":{"AccessToken":"` + falsePositive + `"},"scheme":"OAuth"}}`,
	)

	memDump := memDumpResultFromChunk(data)

	agent := New(DefaultConfig())
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return memDump
	}

	runtimeEnv, source, err := agent.resolveCachePoisonRuntime()
	if err != nil {
		t.Fatalf("expected runtime tuple from endpoint results, got %v", err)
	}
	if source != "memdump" {
		t.Fatalf("expected memdump source, got %q", source)
	}

	want := cachepoison.RuntimeEnvironment{
		RuntimeToken:   runtimeToken,
		ResultsURL:     "https://results.actions.example/_apis/results",
		CacheURL:       "https://cache.actions.example/_apis/artifactcache",
		CacheServiceV2: true,
	}
	if runtimeEnv != want {
		t.Fatalf("unexpected runtime env: %#v", runtimeEnv)
	}
}

func memDumpResultFromChunk(data []byte) *MemDumpResult {
	results := make(chan gump.Result, 8)
	go func() {
		gump.ScanChunk(data, results)
		close(results)
	}()
	secrets, vars, endpoints := collectMemDumpResults(results)
	return &MemDumpResult{Secrets: secrets, Vars: vars, Endpoints: endpoints}
}
