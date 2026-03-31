// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func TestParseArgs(t *testing.T) {
	opts := parseArgs([]string{"--debug", "--benchmark", "1234"})

	if !opts.debug {
		t.Fatalf("expected debug to be enabled")
	}
	if !opts.benchmark {
		t.Fatalf("expected benchmark to be enabled")
	}
	if opts.pidArg != "1234" {
		t.Fatalf("expected pid 1234, got %q", opts.pidArg)
	}
}

func TestRecordDebugValue(t *testing.T) {
	values := make(map[string]debugValue)

	recordDebugValue(values, gump.Result{
		Type:     gump.ResultEndpoint,
		Endpoint: gump.Endpoint{EnvName: "ACTIONS_RESULTS_URL", Value: "https://results.example/_apis/results/123"},
	})
	recordDebugValue(values, gump.Result{
		Type:     gump.ResultEndpoint,
		Endpoint: gump.Endpoint{EnvName: "ACTIONS_RUNTIME_TOKEN", Value: strings.Repeat("t", 2199)},
	})

	if got := values["ACTIONS_RESULTS_URL"].kind; got != "endpoint" {
		t.Fatalf("expected ACTIONS_RESULTS_URL to be recorded as endpoint, got %q", got)
	}
	if got := values["ACTIONS_RUNTIME_TOKEN"].kind; got != "endpoint" {
		t.Fatalf("expected ACTIONS_RUNTIME_TOKEN to be recorded as endpoint, got %q", got)
	}
}

func TestFormatDebugValue(t *testing.T) {
	formatted := formatDebugValue("abcdef")
	if !strings.Contains(formatted, "present:6") {
		t.Fatalf("expected length summary, got %q", formatted)
	}
	if !strings.Contains(formatted, "sha256:") {
		t.Fatalf("expected sha256 summary, got %q", formatted)
	}
	if strings.Contains(formatted, "abcdef") {
		t.Fatalf("expected raw value to stay hidden, got %q", formatted)
	}
}

func TestPrintDebugSummary(t *testing.T) {
	outcome := scanOutcome{
		counts: map[gump.ResultType]int{
			gump.ResultSecret:           1,
			gump.ResultVar:              2,
			gump.ResultTokenPermissions: 0,
			gump.ResultEndpoint:         3,
		},
		stats: &gump.ScanStats{
			RegionsScanned: 42,
			BytesRead:      1337,
			ReadErrors:     1,
		},
		values: map[string]debugValue{
			"ACTIONS_RUNTIME_TOKEN": {
				kind:  "endpoint",
				value: strings.Repeat("t", 2199),
			},
			"ACTIONS_RESULTS_URL": {
				kind:  "endpoint",
				value: "https://results.example/_apis/results/123",
			},
			"ACTIONS_RUNTIME_URL": {
				kind:  "endpoint",
				value: "https://pipelines.example/_apis/runtime",
			},
		},
	}

	var b strings.Builder
	printDebugSummary(&b, outcome)
	output := b.String()

	for _, want := range []string{
		"regions_scanned:",
		"bytes_read:",
		"read_errors:",
		"endpoints:",
		"ACTIONS_RUNTIME_TOKEN:",
		"found-as-endpoint",
		"present:2199",
		"ACTIONS_RESULTS_URL:",
		"ACTIONS_CACHE_URL:",
		"absent",
		"ACTIONS_RUNTIME_URL:",
		"found-as-endpoint",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected debug summary to contain %q, got:\n%s", want, output)
		}
	}
}
