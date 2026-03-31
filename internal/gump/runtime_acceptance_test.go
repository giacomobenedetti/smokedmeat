// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build gumpacceptance
// +build gumpacceptance

package gump

import (
	"slices"
	"strings"
	"testing"
)

func collectAcceptanceResults(data []byte) []Result {
	results := make(chan Result, 100)
	go func() {
		ScanChunk(data, results)
		close(results)
	}()

	var collected []Result
	for result := range results {
		collected = append(collected, result)
	}
	slices.SortFunc(collected, func(a, b Result) int {
		switch {
		case a.Type < b.Type:
			return -1
		case a.Type > b.Type:
			return 1
		case a.Raw < b.Raw:
			return -1
		case a.Raw > b.Raw:
			return 1
		default:
			return 0
		}
	})
	return collected
}

func TestScanChunk_ActionsRuntimeTupleAllowsLongRuntimeToken(t *testing.T) {
	runtimeToken := strings.Repeat("r", 2199)
	data := []byte(
		`[` +
			`{"name":"ACTIONS_RUNTIME_TOKEN","value":"` + runtimeToken + `"},` +
			`{"name":"ACTIONS_RESULTS_URL","value":"https://results.actions.example/_apis/results"},` +
			`{"name":"ACTIONS_CACHE_URL","value":"https://cache.actions.example/_apis/artifactcache"},` +
			`{"name":"ACTIONS_CACHE_SERVICE_V2","value":"true"}` +
			`]`,
	)

	results := collectAcceptanceResults(data)

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	gotVars := map[string]string{}
	for _, result := range results {
		if result.Type != ResultVar {
			t.Fatalf("expected runtime tuple vars, got result type %d", result.Type)
		}
		gotVars[result.Var.Name] = result.Var.Value
	}

	if gotVars["ACTIONS_RUNTIME_TOKEN"] != runtimeToken {
		t.Fatalf("expected runtime token length %d, got %d", len(runtimeToken), len(gotVars["ACTIONS_RUNTIME_TOKEN"]))
	}
	if gotVars["ACTIONS_RESULTS_URL"] != "https://results.actions.example/_apis/results" {
		t.Fatalf("unexpected results url %q", gotVars["ACTIONS_RESULTS_URL"])
	}
	if gotVars["ACTIONS_CACHE_URL"] != "https://cache.actions.example/_apis/artifactcache" {
		t.Fatalf("unexpected cache url %q", gotVars["ACTIONS_CACHE_URL"])
	}
	if gotVars["ACTIONS_CACHE_SERVICE_V2"] != "true" {
		t.Fatalf("unexpected cache service flag %q", gotVars["ACTIONS_CACHE_SERVICE_V2"])
	}
}

func TestScanChunk_PrefersRuntimeTokenBoundToResultsContext(t *testing.T) {
	runtimeToken := strings.Repeat("r", 2199)
	falsePositive := strings.Repeat("f", 279)
	data := []byte(
		`{"name":"SystemVssConnection","authorization":{"parameters":{"AccessToken":"` + runtimeToken + `"},"scheme":"OAuth"},"data":{"CacheServerUrl":"https://cache.actions.example/_apis/artifactcache","ResultsServiceUrl":"https://results.actions.example/_apis/results"}}` +
			`{"name":"UnrelatedConnection","authorization":{"parameters":{"AccessToken":"` + falsePositive + `"},"scheme":"OAuth"}}`,
	)

	results := collectAcceptanceResults(data)

	var runtimeTokens []string
	gotEndpoints := map[string]string{}
	for _, result := range results {
		if result.Type != ResultEndpoint {
			continue
		}
		if result.Endpoint.EnvName == "ACTIONS_RUNTIME_TOKEN" {
			runtimeTokens = append(runtimeTokens, result.Endpoint.Value)
		}
		gotEndpoints[result.Endpoint.EnvName] = result.Endpoint.Value
	}

	if len(runtimeTokens) != 1 {
		t.Fatalf("expected exactly 1 ACTIONS_RUNTIME_TOKEN candidate, got %d", len(runtimeTokens))
	}
	if runtimeTokens[0] != runtimeToken {
		t.Fatalf("expected runtime token length %d, got %d", len(runtimeToken), len(runtimeTokens[0]))
	}
	if gotEndpoints["ACTIONS_RESULTS_URL"] != "https://results.actions.example/_apis/results" {
		t.Fatalf("unexpected results url %q", gotEndpoints["ACTIONS_RESULTS_URL"])
	}
	if gotEndpoints["ACTIONS_CACHE_URL"] != "https://cache.actions.example/_apis/artifactcache" {
		t.Fatalf("unexpected cache url %q", gotEndpoints["ACTIONS_CACHE_URL"])
	}
}
