// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gump

import (
	"encoding/base64"
	"strings"
	"testing"
)

func collectResults(data []byte) []Result {
	results := make(chan Result, 100)
	go func() {
		ScanChunk(data, results)
		close(results)
	}()

	var collected []Result
	for r := range results {
		collected = append(collected, r)
	}
	return collected
}

func TestScanChunk_SingleSecret(t *testing.T) {
	data := []byte(`"system.github.token"{"value":"ghs_xxxxxxxxxxxx","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Type != ResultSecret {
		t.Errorf("expected ResultSecret, got %d", results[0].Type)
	}
	expected := `"GITHUB_TOKEN"{"value":"ghs_xxxxxxxxxxxx","isSecret":true}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
	if results[0].Secret.Name != "GITHUB_TOKEN" {
		t.Errorf("expected name GITHUB_TOKEN, got %s", results[0].Secret.Name)
	}
}

func TestScanChunk_MultipleSecrets(t *testing.T) {
	data := []byte(`"TOKEN_A"{"value":"aaa","isSecret":true}"TOKEN_B"{"value":"bbb","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Raw != `"TOKEN_A"{"value":"aaa","isSecret":true}` {
		t.Errorf("first result mismatch: %q", results[0].Raw)
	}
	if results[1].Raw != `"TOKEN_B"{"value":"bbb","isSecret":true}` {
		t.Errorf("second result mismatch: %q", results[1].Raw)
	}
}

func TestScanChunk_SecretsWithPadding(t *testing.T) {
	data := []byte(`garbage before"SECRET_1"{"value":"val1","isSecret":true}middle padding"SECRET_2"{"value":"val2","isSecret":true}trailing`)
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Raw != `"SECRET_1"{"value":"val1","isSecret":true}` {
		t.Errorf("first result mismatch: %q", results[0].Raw)
	}
	if results[1].Raw != `"SECRET_2"{"value":"val2","isSecret":true}` {
		t.Errorf("second result mismatch: %q", results[1].Raw)
	}
}

func TestScanChunk_NullBytesStripped(t *testing.T) {
	data := []byte("\"TOKEN\"\x00{\x00\"value\":\"secret\x00value\",\"isSecret\":true}")
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := `"TOKEN"{"value":"secretvalue","isSecret":true}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_NoSecrets(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected int
	}{
		{"empty", []byte{}, 0},
		{"random text", []byte("just some random text without secrets"), 0},
		{"partial suffix", []byte(`"isSecret":true`), 0},
		{"partial prefix", []byte(`{"value":"something"`), 0},
		{"json without secret marker", []byte(`"MYVAR"{"value":"abc"}`), 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := collectResults(tc.data)
			if len(results) != tc.expected {
				t.Errorf("expected %d results, got %d: %v", tc.expected, len(results), results)
			}
		})
	}
}

func TestScanChunk_MalformedData(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected int
	}{
		{
			name:     "suffix without prefix",
			data:     []byte(`random","isSecret":true}`),
			expected: 0,
		},
		{
			name:     "prefix without name quotes",
			data:     []byte(`NONAME{"value":"secret","isSecret":true}`),
			expected: 0,
		},
		{
			name:     "only closing quote before prefix",
			data:     []byte(`NAME"{"value":"secret","isSecret":true}`),
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := collectResults(tc.data)
			if len(results) != tc.expected {
				t.Errorf("expected %d results, got %d: %v", tc.expected, len(results), results)
			}
		})
	}
}

func TestScanChunk_LongSecretAccepted(t *testing.T) {
	longValue := strings.Repeat("x", 2100)
	data := []byte(`"NAME"{"value":"` + longValue + `","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected long secret to be accepted, got %d results", len(results))
	}
}

func TestScanChunk_SecretJustUnderLimit(t *testing.T) {
	name := "N"
	valueLen := maxExtractedEntryLen - len(`"N"{"value":"","isSecret":true}`)
	value := strings.Repeat("x", valueLen)
	data := []byte(`"` + name + `"{"value":"` + value + `","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result for secret just under limit, got %d", len(results))
	}
}

func TestScanChunk_EmptyValue(t *testing.T) {
	data := []byte(`"EMPTY"{"value":"","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Raw != `"EMPTY"{"value":"","isSecret":true}` {
		t.Errorf("unexpected result: %q", results[0].Raw)
	}
}

func TestScanChunk_SpecialCharactersInName(t *testing.T) {
	data := []byte(`"MY_SECRET_123_ABC"{"value":"val","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := `"MY_SECRET_123_ABC"{"value":"val","isSecret":true}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_SpecialCharactersInValue(t *testing.T) {
	data := []byte(`"TOKEN"{"value":"abc!@#$%^&*()_+-=[]{}|;':,./<>?","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestScanChunk_LookBackLimit(t *testing.T) {
	padding := strings.Repeat("x", 5000)
	data := []byte(padding + `"TOKEN"{"value":"secret","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := `"TOKEN"{"value":"secret","isSecret":true}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_SecretBeyondLookBackLimit(t *testing.T) {
	padding := strings.Repeat("x", maxExtractedEntryLen+100)
	data := []byte(`"TOKEN"` + padding + `{"value":"secret","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 0 {
		t.Errorf("expected 0 results when name is beyond lookback limit, got %d", len(results))
	}
}

func TestScanChunk_ValuePrefixBeyondLookBackLimit(t *testing.T) {
	padding := strings.Repeat("x", maxExtractedEntryLen+100)
	data := []byte(`"TOKEN"{"value":"` + padding + `secret","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 0 {
		t.Errorf("expected 0 results when value prefix is beyond lookback limit, got %d", len(results))
	}
}

func TestScanChunk_AdjacentSecrets(t *testing.T) {
	data := []byte(`"A"{"value":"1","isSecret":true}"B"{"value":"2","isSecret":true}"C"{"value":"3","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestScanChunk_RealWorldGitHubToken(t *testing.T) {
	data := []byte(`"system.github.token"{"value":"ghs_1234567890abcdefghijklmnopqrstuvwx","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Secret.Name != "GITHUB_TOKEN" {
		t.Error("result should have GITHUB_TOKEN name (normalized from system.github.token)")
	}
	if !strings.HasPrefix(results[0].Secret.Value, "ghs_") {
		t.Error("result should contain the token value")
	}
}

func TestScanChunk_SecretAtStartOfData(t *testing.T) {
	data := []byte(`"FIRST"{"value":"val","isSecret":true}trailing garbage`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Raw != `"FIRST"{"value":"val","isSecret":true}` {
		t.Errorf("unexpected result: %q", results[0].Raw)
	}
}

func TestScanChunk_SecretAtEndOfData(t *testing.T) {
	data := []byte(`leading garbage"LAST"{"value":"val","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Raw != `"LAST"{"value":"val","isSecret":true}` {
		t.Errorf("unexpected result: %q", results[0].Raw)
	}
}

func TestFindNameStart_Normal(t *testing.T) {
	data := []byte(`"SECRET_NAME"`)
	idx := findNameStart(data)
	if idx != 0 {
		t.Errorf("expected 0, got %d", idx)
	}
}

func TestFindNameStart_WithPrefix(t *testing.T) {
	data := []byte(`prefix"SECRET_NAME"`)
	idx := findNameStart(data)
	if idx != 6 {
		t.Errorf("expected 6, got %d", idx)
	}
}

func TestFindNameStart_EmptyData(t *testing.T) {
	data := []byte{}
	idx := findNameStart(data)
	if idx != -1 {
		t.Errorf("expected -1, got %d", idx)
	}
}

func TestFindNameStart_NoQuotes(t *testing.T) {
	data := []byte(`no quotes here`)
	idx := findNameStart(data)
	if idx != -1 {
		t.Errorf("expected -1, got %d", idx)
	}
}

func TestFindNameStart_SingleQuote(t *testing.T) {
	data := []byte(`only one"`)
	idx := findNameStart(data)
	if idx != -1 {
		t.Errorf("expected -1 for single quote, got %d", idx)
	}
}

func TestFindNameStart_MultipleQuotedStrings(t *testing.T) {
	data := []byte(`"first""second""third"`)
	idx := findNameStart(data)
	if idx != 15 {
		t.Errorf("expected 15 (start of 'third'), got %d", idx)
	}
}

func TestFindNameStart_QuoteAtStart(t *testing.T) {
	data := []byte(`"NAME"`)
	idx := findNameStart(data)
	if idx != 0 {
		t.Errorf("expected 0, got %d", idx)
	}
}

func TestFindNameStart_EmptyName(t *testing.T) {
	data := []byte(`""`)
	idx := findNameStart(data)
	if idx != 0 {
		t.Errorf("expected 0, got %d", idx)
	}
}

func TestEncodeSecrets_Empty(t *testing.T) {
	result := EncodeSecrets(map[string]bool{})
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestEncodeSecrets_Nil(t *testing.T) {
	result := EncodeSecrets(nil)
	if result != "" {
		t.Errorf("expected empty string for nil map, got %q", result)
	}
}

func TestEncodeSecrets_Single(t *testing.T) {
	secrets := map[string]bool{"secret1": true}
	result := EncodeSecrets(secrets)

	decoded := decodeDoubleBase64(t, result)
	if decoded != "secret1" {
		t.Errorf("expected 'secret1', got %q", decoded)
	}
}

func TestEncodeSecrets_Multiple(t *testing.T) {
	secrets := map[string]bool{
		"zebra": true,
		"alpha": true,
		"mango": true,
	}
	result := EncodeSecrets(secrets)

	decoded := decodeDoubleBase64(t, result)
	expected := "alpha\nmango\nzebra"
	if decoded != expected {
		t.Errorf("expected sorted %q, got %q", expected, decoded)
	}
}

func TestEncodeSecrets_SpecialCharacters(t *testing.T) {
	secrets := map[string]bool{
		"secret!@#$%": true,
		"pass=word":   true,
	}
	result := EncodeSecrets(secrets)

	decoded := decodeDoubleBase64(t, result)
	if !strings.Contains(decoded, "secret!@#$%") {
		t.Error("decoded should contain special characters")
	}
	if !strings.Contains(decoded, "pass=word") {
		t.Error("decoded should contain equals sign")
	}
}

func TestEncodeSecrets_FalseValuesIgnored(t *testing.T) {
	secrets := map[string]bool{
		"included": true,
		"excluded": false,
	}
	result := EncodeSecrets(secrets)

	decoded := decodeDoubleBase64(t, result)
	lines := strings.Split(decoded, "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines (both keys present), got %d: %v", len(lines), lines)
	}
}

func decodeDoubleBase64(t *testing.T, encoded string) string {
	t.Helper()
	first, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("first base64 decode failed: %v", err)
	}
	second, err := base64.StdEncoding.DecodeString(string(first))
	if err != nil {
		t.Fatalf("second base64 decode failed: %v", err)
	}
	return string(second)
}

func TestScanChunk_BackwardCompatibility(t *testing.T) {
	data := []byte(`"system.github.token"{"value":"ghs_xxx","isSecret":true}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !strings.HasPrefix(r.Raw, `"GITHUB_TOKEN"`) {
		t.Error("result should start with GITHUB_TOKEN (normalized)")
	}
	if !strings.Contains(r.Raw, `"value":"ghs_xxx"`) {
		t.Error("result should contain the value")
	}
	if !strings.HasSuffix(r.Raw, `"isSecret":true}`) {
		t.Error("result should end with isSecret marker and closing brace")
	}
}

func TestScanChunk_ExactOutputFormat(t *testing.T) {
	input := `"system.github.token"{"value":"ghs_xxx","isSecret":true}`
	expected := `"GITHUB_TOKEN"{"value":"ghs_xxx","isSecret":true}`
	data := []byte(input)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Raw != expected {
		t.Errorf("output should be normalized.\nExpected: %s\nGot: %s", expected, results[0].Raw)
	}
}

func TestScanChunk_GitHubTokenFiltered(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"GITHUB_TOKEN uppercase", []byte(`"GITHUB_TOKEN"{"value":"ghs_xxx","isSecret":true}`)},
		{"github_token lowercase", []byte(`"github_token"{"value":"ghs_xxx","isSecret":true}`)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := collectResults(tc.data)
			if len(results) != 0 {
				t.Errorf("expected %s to be filtered out, got %d results: %v", tc.name, len(results), results)
			}
		})
	}
}

func TestScanChunk_TokenPermissions_Single(t *testing.T) {
	data := []byte(`"system.github.token.permissions"{"value":"{\"actions\":\"write\",\"contents\":\"read\"}"}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Type != ResultTokenPermissions {
		t.Error("result should be ResultTokenPermissions")
	}
	if results[0].TokenPermissions["actions"] != "write" {
		t.Error("result should contain actions permission")
	}
}

func TestScanChunk_TokenPermissions_Multiple(t *testing.T) {
	data := []byte(`"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}padding"system.github.token.permissions"{"value":"{\"contents\":\"read\"}"}`)
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestScanChunk_TokenPermissions_WithPadding(t *testing.T) {
	data := []byte(`garbage before"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}trailing garbage`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].TokenPermissions["actions"] != "write" {
		t.Error("result should contain actions permission")
	}
}

func TestScanChunk_TokenPermissions_NullBytes(t *testing.T) {
	data := []byte("\"system.github.token.permissions\"\x00{\"value\":\"{\\\"actions\\\":\\\"write\\\"}\"}")
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestScanChunk_TokenPermissions_NoPermissions(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"random text", []byte("just some random text")},
		{"partial name", []byte(`"GITHUB_TOKEN"`)},
		{"wrong name", []byte(`"system.github.other"{"value":"{\"x\":\"y\"}"}`)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := collectResults(tc.data)
			for _, r := range results {
				if r.Type == ResultTokenPermissions {
					t.Errorf("unexpected permissions result: %v", r.Raw)
				}
			}
		})
	}
}

func TestScanChunk_TokenPermissions_MalformedData(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected int
	}{
		{
			name:     "name without value",
			data:     []byte(`"system.github.token.permissions"random`),
			expected: 0,
		},
		{
			name:     "value too far from name",
			data:     []byte(`"system.github.token.permissions"` + strings.Repeat("x", 100) + `{"value":"{\"a\":\"b\"}"}`),
			expected: 0,
		},
		{
			name:     "value not starting with brace",
			data:     []byte(`"system.github.token.permissions"{"value":"notjson"}`),
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := collectResults(tc.data)
			permCount := 0
			for _, r := range results {
				if r.Type == ResultTokenPermissions {
					permCount++
				}
			}
			if permCount != tc.expected {
				t.Errorf("expected %d permission results, got %d", tc.expected, permCount)
			}
		})
	}
}

func TestScanChunk_TokenPermissions_LongValue(t *testing.T) {
	longJSON := `{\"` + strings.Repeat("x", maxExtractedEntryLen+100) + `\":\"y\"}`
	data := []byte(`"system.github.token.permissions"{"value":"` + longJSON + `"}`)
	results := collectResults(data)

	permCount := 0
	for _, r := range results {
		if r.Type == ResultTokenPermissions {
			permCount++
		}
	}
	if permCount != 0 {
		t.Errorf("expected long permission to be rejected, got %d results", permCount)
	}
}

func TestScanChunk_TokenPermissions_EmptyValue(t *testing.T) {
	data := []byte(`"system.github.token.permissions"{"value":""}`)
	results := collectResults(data)

	permCount := 0
	for _, r := range results {
		if r.Type == ResultTokenPermissions {
			permCount++
		}
	}
	if permCount != 0 {
		t.Errorf("expected empty permission to be rejected (doesn't start with {), got %d results", permCount)
	}
}

func TestScanChunk_TokenPermissions_WithSecrets(t *testing.T) {
	data := []byte(`"system.github.token"{"value":"ghs_xxx","isSecret":true}"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}`)
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results (secret + permissions), got %d", len(results))
	}

	hasSecret := false
	hasPerms := false
	for _, r := range results {
		if r.Type == ResultSecret {
			hasSecret = true
		}
		if r.Type == ResultTokenPermissions {
			hasPerms = true
		}
	}
	if !hasSecret {
		t.Error("should have found secret (normalized to GITHUB_TOKEN)")
	}
	if !hasPerms {
		t.Error("should have found permissions")
	}
}

func TestScanChunk_TokenPermissions_RealWorldFormat(t *testing.T) {
	data := []byte(`"system.github.token.permissions"{"value":"{\"actions\":\"write\",\"contents\":\"read\",\"metadata\":\"read\",\"pull-requests\":\"write\"}"}`)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	expected := `"system.github.token.permissions"{"value":"{\"actions\":\"write\",\"contents\":\"read\",\"metadata\":\"read\",\"pull-requests\":\"write\"}"}`
	if results[0].Raw != expected {
		t.Errorf("output mismatch.\nExpected: %s\nGot: %s", expected, results[0].Raw)
	}
}

func TestScanChunk_TokenPermissions_ExactOutputFormat(t *testing.T) {
	input := `"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}`
	data := []byte(input)
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Raw != input {
		t.Errorf("output should exactly match input format.\nExpected: %s\nGot: %s", input, results[0].Raw)
	}
}

func TestParseTokenPermissions(t *testing.T) {
	input := `"system.github.token.permissions"{"value":"{\"Actions\":\"read\",\"Contents\":\"write\",\"Metadata\":\"read\"}"}`
	perms, err := ParseTokenPermissions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(perms) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(perms))
	}
	if perms["Actions"] != "read" {
		t.Errorf("expected Actions=read, got %s", perms["Actions"])
	}
	if perms["Contents"] != "write" {
		t.Errorf("expected Contents=write, got %s", perms["Contents"])
	}
	if perms["Metadata"] != "read" {
		t.Errorf("expected Metadata=read, got %s", perms["Metadata"])
	}
}

func TestParseTokenPermissions_Empty(t *testing.T) {
	input := `"system.github.token.permissions"{"value":"{}"}`
	perms, err := ParseTokenPermissions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms) != 0 {
		t.Errorf("expected 0 permissions, got %d", len(perms))
	}
}

func TestParseTokenPermissions_Invalid(t *testing.T) {
	_, err := ParseTokenPermissions(`"OTHER"{"value":"x"}`)
	if err == nil {
		t.Error("expected error for non-permissions input")
	}
}

func TestIsTokenPermissions(t *testing.T) {
	if !IsTokenPermissions(`"system.github.token.permissions"{"value":"{}"}`) {
		t.Error("should return true for permissions")
	}
	if IsTokenPermissions(`"GITHUB_TOKEN"{"value":"x","isSecret":true}`) {
		t.Error("should return false for secrets")
	}
}

func TestParseSecret(t *testing.T) {
	input := `"GITHUB_TOKEN"{"value":"ghs_abc123xyz","isSecret":true}`
	secret, err := ParseSecret(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Name != "GITHUB_TOKEN" {
		t.Errorf("expected name GITHUB_TOKEN, got %s", secret.Name)
	}
	if secret.Value != "ghs_abc123xyz" {
		t.Errorf("expected value ghs_abc123xyz, got %s", secret.Value)
	}
}

func TestParseSecret_RejectsPermissions(t *testing.T) {
	_, err := ParseSecret(`"system.github.token.permissions"{"value":"{}"}`)
	if err == nil {
		t.Error("expected error when parsing permissions as secret")
	}
}

func BenchmarkScanChunk(b *testing.B) {
	data := []byte(strings.Repeat(`padding"TOKEN"{"value":"secretvalue","isSecret":true}`, 100))
	results := make(chan Result, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanChunk(data, results)
		for len(results) > 0 {
			<-results
		}
	}
}

func BenchmarkScanChunk_LargeChunk(b *testing.B) {
	padding := strings.Repeat("x", 10000)
	data := []byte(padding + `"TOKEN"{"value":"secret","isSecret":true}` + padding)
	results := make(chan Result, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanChunk(data, results)
		for len(results) > 0 {
			<-results
		}
	}
}

func BenchmarkScanChunk_WithPermissions(b *testing.B) {
	data := []byte(strings.Repeat(`padding"TOKEN"{"value":"secretvalue","isSecret":true}"system.github.token.permissions"{"value":"{\"actions\":\"write\"}"}`, 50))
	results := make(chan Result, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanChunk(data, results)
		for len(results) > 0 {
			<-results
		}
	}
}

func wrapVarsContext(entries string) string {
	return `"vars":{"t":2,"d":[` + entries + `]}`
}

func TestScanChunk_SingleVar(t *testing.T) {
	data := []byte(wrapVarsContext(`{"k":"AWS_DEPLOY_ROLE_ARN","v":"arn:aws:iam::123456789012:role/deploy"}`))
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Type != ResultVar {
		t.Errorf("expected ResultVar, got %d", results[0].Type)
	}
	if results[0].Var.Name != "AWS_DEPLOY_ROLE_ARN" {
		t.Errorf("expected name AWS_DEPLOY_ROLE_ARN, got %s", results[0].Var.Name)
	}
	if results[0].Var.Value != "arn:aws:iam::123456789012:role/deploy" {
		t.Errorf("expected value arn:aws:iam::123456789012:role/deploy, got %s", results[0].Var.Value)
	}
	expected := `{"k":"AWS_DEPLOY_ROLE_ARN","v":"arn:aws:iam::123456789012:role/deploy"}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_MultipleVars(t *testing.T) {
	data := []byte(wrapVarsContext(`{"k":"VAR_A","v":"aaa"},{"k":"VAR_B","v":"bbb"}`))
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Raw != `{"k":"VAR_A","v":"aaa"}` {
		t.Errorf("first result mismatch: %q", results[0].Raw)
	}
	if results[1].Raw != `{"k":"VAR_B","v":"bbb"}` {
		t.Errorf("second result mismatch: %q", results[1].Raw)
	}
}

func TestScanChunk_VarsWithPadding(t *testing.T) {
	data := []byte(`garbage before` + wrapVarsContext(`{"k":"VAR_1","v":"val1"},{"k":"VAR_2","v":"val2"}`) + `trailing`)
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Raw != `{"k":"VAR_1","v":"val1"}` {
		t.Errorf("first result mismatch: %q", results[0].Raw)
	}
	if results[1].Raw != `{"k":"VAR_2","v":"val2"}` {
		t.Errorf("second result mismatch: %q", results[1].Raw)
	}
}

func TestScanChunk_VarsWithSecrets(t *testing.T) {
	data := []byte(`"MY_SECRET"{"value":"s3cret","isSecret":true}` + wrapVarsContext(`{"k":"MY_VAR","v":"us-east-1"}`))
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results (secret + var), got %d", len(results))
	}

	hasSecret := false
	hasVar := false
	for _, r := range results {
		if r.Type == ResultSecret {
			hasSecret = true
		}
		if r.Type == ResultVar {
			hasVar = true
		}
	}
	if !hasSecret {
		t.Error("should have found secret")
	}
	if !hasVar {
		t.Error("should have found var")
	}
}

func TestScanChunk_VarObjectFormat(t *testing.T) {
	data := []byte(wrapVarsContext(`{"k":"MYVAR","v":{"s":"val"}}`))
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := `{"k":"MYVAR","v":{"s":"val"}}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_VarBothFormats(t *testing.T) {
	data := []byte(wrapVarsContext(`{"k":"BARE","v":"val1"},{"k":"OBJ","v":{"s":"val2"}}`))
	results := collectResults(data)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Raw != `{"k":"BARE","v":"val1"}` {
		t.Errorf("first result mismatch: %q", results[0].Raw)
	}
	if results[1].Raw != `{"k":"OBJ","v":{"s":"val2"}}` {
		t.Errorf("second result mismatch: %q", results[1].Raw)
	}
}

func TestScanChunk_VarNullBytesStripped(t *testing.T) {
	data := []byte("{\"k\":\"vars\",\"v\":{\"t\":2,\"d\":[{\"k\":\"\x00MYVAR\",\"v\":\"some\x00value\"}]}}")
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := `{"k":"MYVAR","v":"somevalue"}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_VarLongValueRejected(t *testing.T) {
	longValue := strings.Repeat("x", maxExtractedEntryLen+100)
	data := []byte(wrapVarsContext(`{"k":"MYVAR","v":"` + longValue + `"}`))
	results := collectResults(data)

	if len(results) != 0 {
		t.Errorf("expected long var to be rejected, got %d results", len(results))
	}
}

func TestScanChunk_VarWithPaddingBefore(t *testing.T) {
	padding := strings.Repeat("x", 5000)
	data := []byte(padding + wrapVarsContext(`{"k":"MYVAR","v":"val"}`))
	results := collectResults(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := `{"k":"MYVAR","v":"val"}`
	if results[0].Raw != expected {
		t.Errorf("expected %q, got %q", expected, results[0].Raw)
	}
}

func TestScanChunk_VarIgnoresOtherContexts(t *testing.T) {
	data := []byte(`{"github":{"t":2,"d":[{"k":"repository","v":"owner/repo"},{"k":"sha","v":"abc123"}]},"runner":{"t":2,"d":[{"k":"os","v":"Linux"}]},"vars":{"t":2,"d":[{"k":"MY_VAR","v":"my_value"}]}}`)
	results := collectResults(data)

	varCount := 0
	for _, r := range results {
		if r.Type == ResultVar {
			varCount++
		}
	}
	if varCount != 1 {
		t.Fatalf("expected 1 var result, got %d: %v", varCount, results)
	}
}

func TestScanChunk_VarDictionaryContextDataFormat(t *testing.T) {
	data := []byte(`{"k":"vars","v":{"t":2,"d":[{"k":"MY_VAR","v":"my_value"}]}}`)
	results := collectResults(data)

	varCount := 0
	for _, r := range results {
		if r.Type == ResultVar {
			varCount++
		}
	}
	if varCount != 1 {
		t.Fatalf("expected 1 var result, got %d: %v", varCount, results)
	}
}

func TestIsVar(t *testing.T) {
	if !IsVar(`{"k":"MYVAR","v":"val"}`) {
		t.Error("should return true for bare string vars")
	}
	if !IsVar(`{"k":"MYVAR","v":{"s":"val"}}`) {
		t.Error("should return true for object string vars")
	}
	if IsVar(`"TOKEN"{"value":"x","isSecret":true}`) {
		t.Error("should return false for secrets")
	}
	if IsVar(`"system.github.token.permissions"{"value":"{}"}`) {
		t.Error("should return false for permissions")
	}
}

func TestParseVar(t *testing.T) {
	v, err := ParseVar(`{"k":"AWS_REGION","v":"us-east-1"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "AWS_REGION" {
		t.Errorf("expected name AWS_REGION, got %s", v.Name)
	}
	if v.Value != "us-east-1" {
		t.Errorf("expected value us-east-1, got %s", v.Value)
	}
}

func TestParseVar_ObjectFormat(t *testing.T) {
	v, err := ParseVar(`{"k":"AWS_REGION","v":{"s":"us-east-1"}}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "AWS_REGION" {
		t.Errorf("expected name AWS_REGION, got %s", v.Name)
	}
	if v.Value != "us-east-1" {
		t.Errorf("expected value us-east-1, got %s", v.Value)
	}
}

func TestParseVar_RejectsSecrets(t *testing.T) {
	_, err := ParseVar(`"TOKEN"{"value":"secret","isSecret":true}`)
	if err == nil {
		t.Error("expected error when parsing secret as var")
	}
}

func TestParseVar_RejectsPermissions(t *testing.T) {
	_, err := ParseVar(`"system.github.token.permissions"{"value":"{}"}`)
	if err == nil {
		t.Error("expected error when parsing permissions as var")
	}
}

func BenchmarkScanChunk_WithVars(b *testing.B) {
	data := []byte(strings.Repeat(`padding"TOKEN"{"value":"secretvalue","isSecret":true}`+wrapVarsContext(`{"k":"MYVAR","v":"us-east-1"}`), 50))
	results := make(chan Result, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanChunk(data, results)
		for len(results) > 0 {
			<-results
		}
	}
}
