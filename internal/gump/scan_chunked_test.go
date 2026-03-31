// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gump

import (
	"bytes"
	"strings"
	"testing"
)

func collectChunkedResults(data []byte, chunkSize, overlap int) []Result {
	results := make(chan Result, 100)
	emitter := newResultEmitter(results)

	scanReadableRegion(bytes.NewReader(data), 0, int64(len(data)), chunkSize, overlap, func(chunk []byte) {
		scanChunkWithEmitter(chunk, emitter.emit)
	})
	close(results)

	var collected []Result
	for r := range results {
		collected = append(collected, r)
	}
	return collected
}

func collectVarResults(results []Result) map[string]string {
	collected := make(map[string]string)
	for _, r := range results {
		if r.Type == ResultVar {
			collected[r.Var.Name] = r.Var.Value
		}
	}
	return collected
}

func collectEndpointResults(results []Result) map[string]string {
	collected := make(map[string]string)
	for _, r := range results {
		if r.Type == ResultEndpoint {
			collected[r.Endpoint.EnvName] = r.Endpoint.Value
		}
	}
	return collected
}

func collectNamedEndpointValues(results []Result, name string) []string {
	var collected []string
	for _, r := range results {
		if r.Type == ResultEndpoint && r.Endpoint.EnvName == name {
			collected = append(collected, r.Endpoint.Value)
		}
	}
	return collected
}

func TestScanChunk_RecoversGitHubActionsRuntimeTupleFromNameValueLayout(t *testing.T) {
	runtimeToken := strings.Repeat("t", 2199)
	data := []byte(`[` +
		`{"name":"ACTIONS_RUNTIME_TOKEN","value":"` + runtimeToken + `"},` +
		`{"name":"ACTIONS_RESULTS_URL","value":"https://results.example/_apis/results/123"},` +
		`{"name":"ACTIONS_CACHE_URL","value":"https://cache.example/_apis/artifactcache"},` +
		`{"name":"ACTIONS_CACHE_SERVICE_V2","value":"true"}` +
		`]`)

	results := collectResults(data)
	vars := collectVarResults(results)

	if len(vars) != 4 {
		t.Fatalf("expected 4 runtime tuple vars, got %d: %#v", len(vars), vars)
	}
	if vars["ACTIONS_RUNTIME_TOKEN"] != runtimeToken {
		t.Fatalf("expected long runtime token to be recovered, got length %d", len(vars["ACTIONS_RUNTIME_TOKEN"]))
	}
	if vars["ACTIONS_RESULTS_URL"] != "https://results.example/_apis/results/123" {
		t.Fatalf("unexpected ACTIONS_RESULTS_URL: %q", vars["ACTIONS_RESULTS_URL"])
	}
	if vars["ACTIONS_CACHE_URL"] != "https://cache.example/_apis/artifactcache" {
		t.Fatalf("unexpected ACTIONS_CACHE_URL: %q", vars["ACTIONS_CACHE_URL"])
	}
	if vars["ACTIONS_CACHE_SERVICE_V2"] != "true" {
		t.Fatalf("unexpected ACTIONS_CACHE_SERVICE_V2: %q", vars["ACTIONS_CACHE_SERVICE_V2"])
	}
}

func TestScanChunk_RecoversEnvLikeKVOutsideVarsContext(t *testing.T) {
	data := []byte(`{"runtime":{"t":2,"d":[{"k":"ACTIONS_RESULTS_URL","v":"https://results.example/_apis/results/123"},{"k":"ACTIONS_CACHE_SERVICE_V2","v":"true"}]},"github":{"t":2,"d":[{"k":"repository","v":"owner/repo"},{"k":"sha","v":"abc123"}]}}`)

	results := collectResults(data)
	vars := collectVarResults(results)

	if len(vars) != 2 {
		t.Fatalf("expected 2 env-like vars outside vars context, got %d: %#v", len(vars), vars)
	}
	if _, ok := vars["repository"]; ok {
		t.Fatalf("unexpected non-env repository entry recovered: %#v", vars)
	}
	if vars["ACTIONS_RESULTS_URL"] != "https://results.example/_apis/results/123" {
		t.Fatalf("unexpected ACTIONS_RESULTS_URL: %q", vars["ACTIONS_RESULTS_URL"])
	}
	if vars["ACTIONS_CACHE_SERVICE_V2"] != "true" {
		t.Fatalf("unexpected ACTIONS_CACHE_SERVICE_V2: %q", vars["ACTIONS_CACHE_SERVICE_V2"])
	}
}

func TestScanReadableRegion_FindsTargetAfterFirstTenMiB(t *testing.T) {
	data := []byte(strings.Repeat("x", 10*1024*1024+512) +
		`{"ACTIONS_CACHE_URL":"https://cache.example/_apis/artifactcache"}`)

	results := collectChunkedResults(data, 10*1024*1024, 4096)
	vars := collectVarResults(results)

	if vars["ACTIONS_CACHE_URL"] != "https://cache.example/_apis/artifactcache" {
		t.Fatalf("expected ACTIONS_CACHE_URL after first 10 MiB to be recovered, got %#v", vars)
	}
}

func TestScanReadableRegion_FindsBoundarySplitTargetWithOverlap(t *testing.T) {
	data := []byte(strings.Repeat("x", 96) +
		`{"ACTIONS_RESULTS_URL":"https://results.example/_apis/results/123"}`)

	results := collectChunkedResults(data, 128, 96)
	vars := collectVarResults(results)

	if len(vars) != 1 {
		t.Fatalf("expected 1 boundary-split var, got %d: %#v", len(vars), vars)
	}
	if vars["ACTIONS_RESULTS_URL"] != "https://results.example/_apis/results/123" {
		t.Fatalf("unexpected ACTIONS_RESULTS_URL: %q", vars["ACTIONS_RESULTS_URL"])
	}
}

func TestScanChunk_IgnoresStandaloneAccessTokenWithoutRuntimeContext(t *testing.T) {
	jwt := strings.Repeat("t", 2199)
	data := []byte(`{"authorization":{"parameters":{"AccessToken":"` + jwt + `"},"scheme":"OAuth"}}`)

	results := collectResults(data)
	endpoints := collectEndpointResults(results)

	if _, ok := endpoints["ACTIONS_RUNTIME_TOKEN"]; ok {
		t.Fatalf("unexpected standalone ACTIONS_RUNTIME_TOKEN: got length %d", len(endpoints["ACTIONS_RUNTIME_TOKEN"]))
	}
}

func TestScanChunk_RecoversEndpointDataURLs(t *testing.T) {
	data := []byte(`{"data":{"CacheServerUrl":"https://artifactcache.actions.githubusercontent.com/abc123/","ResultsServiceUrl":"https://results.actions.githubusercontent.com/abc123/","PipelinesServiceUrl":"https://pipelines.actions.githubusercontent.com/abc123/","GenerateIdTokenUrl":"https://vstoken.actions.githubusercontent.com/abc123/"}}`)

	results := collectResults(data)
	endpoints := collectEndpointResults(results)

	if endpoints["ACTIONS_CACHE_URL"] != "https://artifactcache.actions.githubusercontent.com/abc123/" {
		t.Fatalf("expected ACTIONS_CACHE_URL, got %q", endpoints["ACTIONS_CACHE_URL"])
	}
	if endpoints["ACTIONS_RESULTS_URL"] != "https://results.actions.githubusercontent.com/abc123/" {
		t.Fatalf("expected ACTIONS_RESULTS_URL, got %q", endpoints["ACTIONS_RESULTS_URL"])
	}
	if endpoints["ACTIONS_RUNTIME_URL"] != "https://pipelines.actions.githubusercontent.com/abc123/" {
		t.Fatalf("expected ACTIONS_RUNTIME_URL, got %q", endpoints["ACTIONS_RUNTIME_URL"])
	}
	if endpoints["ACTIONS_ID_TOKEN_REQUEST_URL"] != "https://vstoken.actions.githubusercontent.com/abc123/" {
		t.Fatalf("expected ACTIONS_ID_TOKEN_REQUEST_URL, got %q", endpoints["ACTIONS_ID_TOKEN_REQUEST_URL"])
	}
}

func TestScanChunk_RecoversFullEndpointObject(t *testing.T) {
	jwt := strings.Repeat("e", 2199)
	data := []byte(`{"name":"SystemVssConnection","url":"https://pipelines.actions.githubusercontent.com/xxx/","authorization":{"parameters":{"AccessToken":"` + jwt + `"},"scheme":"OAuth"},"data":{"CacheServerUrl":"https://artifactcache.actions.githubusercontent.com/xxx/","ResultsServiceUrl":"https://results.actions.githubusercontent.com/xxx/"}}`)

	results := collectResults(data)
	endpoints := collectEndpointResults(results)

	if len(endpoints["ACTIONS_RUNTIME_TOKEN"]) != 2199 {
		t.Fatalf("expected ACTIONS_RUNTIME_TOKEN length 2199, got %d", len(endpoints["ACTIONS_RUNTIME_TOKEN"]))
	}
	if endpoints["ACTIONS_CACHE_URL"] != "https://artifactcache.actions.githubusercontent.com/xxx/" {
		t.Fatalf("unexpected ACTIONS_CACHE_URL: %q", endpoints["ACTIONS_CACHE_URL"])
	}
	if endpoints["ACTIONS_RESULTS_URL"] != "https://results.actions.githubusercontent.com/xxx/" {
		t.Fatalf("unexpected ACTIONS_RESULTS_URL: %q", endpoints["ACTIONS_RESULTS_URL"])
	}
}

func TestScanChunk_RuntimeEndpointObjectBeatsStandaloneAccessTokenFalsePositive(t *testing.T) {
	shortToken := strings.Repeat("s", 279)
	longToken := strings.Repeat("r", 2199)
	data := []byte(
		`{"authorization":{"parameters":{"AccessToken":"` + shortToken + `"},"scheme":"OAuth"}}` +
			`{"name":"SystemVssConnection","url":"https://pipelines.actions.githubusercontent.com/xxx/","authorization":{"parameters":{"AccessToken":"` + longToken + `"},"scheme":"OAuth"},"data":{"CacheServerUrl":"https://artifactcache.actions.githubusercontent.com/xxx/","ResultsServiceUrl":"https://results.actions.githubusercontent.com/xxx/"}}`,
	)

	results := collectResults(data)
	runtimeTokens := collectNamedEndpointValues(results, "ACTIONS_RUNTIME_TOKEN")
	endpoints := collectEndpointResults(results)

	if len(runtimeTokens) != 1 {
		t.Fatalf("expected exactly 1 contextual ACTIONS_RUNTIME_TOKEN, got %d", len(runtimeTokens))
	}
	if runtimeTokens[0] != longToken {
		t.Fatalf("expected contextual ACTIONS_RUNTIME_TOKEN length 2199, got %d", len(runtimeTokens[0]))
	}
	if endpoints["ACTIONS_CACHE_URL"] != "https://artifactcache.actions.githubusercontent.com/xxx/" {
		t.Fatalf("unexpected ACTIONS_CACHE_URL: %q", endpoints["ACTIONS_CACHE_URL"])
	}
	if endpoints["ACTIONS_RESULTS_URL"] != "https://results.actions.githubusercontent.com/xxx/" {
		t.Fatalf("unexpected ACTIONS_RESULTS_URL: %q", endpoints["ACTIONS_RESULTS_URL"])
	}
}

func TestScanChunk_EndpointKeyWithChunkedScanning(t *testing.T) {
	jwt := strings.Repeat("j", 2199)
	payload := `{"name":"SystemVssConnection","authorization":{"parameters":{"AccessToken":"` + jwt + `"}},"data":{"CacheServerUrl":"https://artifactcache.actions.githubusercontent.com/xxx/","ResultsServiceUrl":"https://results.actions.githubusercontent.com/xxx/"}}`
	data := []byte(strings.Repeat("x", 10*1024*1024+512) + payload)

	results := collectChunkedResults(data, 4*1024*1024, 64*1024)
	endpoints := collectEndpointResults(results)

	if endpoints["ACTIONS_RUNTIME_TOKEN"] != jwt {
		t.Fatalf("expected ACTIONS_RUNTIME_TOKEN after 10 MiB, got length %d", len(endpoints["ACTIONS_RUNTIME_TOKEN"]))
	}
}

func TestParseVar_EnvMapLayout(t *testing.T) {
	v, err := ParseVar(`"ACTIONS_RESULTS_URL":"https://results.example/_apis/results/123"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "ACTIONS_RESULTS_URL" {
		t.Fatalf("expected ACTIONS_RESULTS_URL, got %q", v.Name)
	}
	if v.Value != "https://results.example/_apis/results/123" {
		t.Fatalf("unexpected value: %q", v.Value)
	}
}

func TestScanChunk_EndpointResultsNotInVars(t *testing.T) {
	jwt := strings.Repeat("t", 100)
	data := []byte(`{"name":"SystemVssConnection","authorization":{"parameters":{"AccessToken":"` + jwt + `"}},"data":{"CacheServerUrl":"https://artifactcache.actions.githubusercontent.com/xxx/"}}`)

	results := collectResults(data)
	vars := collectVarResults(results)
	endpoints := collectEndpointResults(results)

	if _, ok := vars["ACTIONS_RUNTIME_TOKEN"]; ok {
		t.Fatal("endpoint result must not appear in var results")
	}
	if endpoints["ACTIONS_RUNTIME_TOKEN"] != jwt {
		t.Fatalf("expected endpoint ACTIONS_RUNTIME_TOKEN, got %q", endpoints["ACTIONS_RUNTIME_TOKEN"])
	}
}

func TestScanChunk_VarResultsNotInEndpoints(t *testing.T) {
	data := []byte(wrapVarsContext(`{"k":"MY_VAR","v":"some_value"}`))

	results := collectResults(data)
	vars := collectVarResults(results)
	endpoints := collectEndpointResults(results)

	if vars["MY_VAR"] != "some_value" {
		t.Fatalf("expected var MY_VAR, got %q", vars["MY_VAR"])
	}
	if len(endpoints) != 0 {
		t.Fatalf("var result must not appear in endpoint results, got %v", endpoints)
	}
}

func TestParseVar_NameValueLayout(t *testing.T) {
	v, err := ParseVar(`{"name":"ACTIONS_CACHE_SERVICE_V2","value":"true"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "ACTIONS_CACHE_SERVICE_V2" {
		t.Fatalf("expected ACTIONS_CACHE_SERVICE_V2, got %q", v.Name)
	}
	if v.Value != "true" {
		t.Fatalf("unexpected value: %q", v.Value)
	}
}
