// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func recordDebugValue(values map[string]debugValue, r gump.Result) {
	name, value, kind, ok := extractDebugValue(r)
	if !ok {
		return
	}
	if _, exists := values[name]; exists {
		return
	}
	values[name] = debugValue{
		kind:  kind,
		value: value,
	}
}

func extractDebugValue(r gump.Result) (name, value, kind string, ok bool) {
	switch r.Type {
	case gump.ResultSecret:
		return r.Secret.Name, r.Secret.Value, "secret", r.Secret.Name != ""
	case gump.ResultVar:
		return r.Var.Name, r.Var.Value, "var", r.Var.Name != ""
	case gump.ResultEndpoint:
		return r.Endpoint.EnvName, r.Endpoint.Value, "endpoint", r.Endpoint.EnvName != ""
	default:
		return "", "", "", false
	}
}

func formatDebugValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("present:%d sha256:%s", len(value), hex.EncodeToString(sum[:6]))
}
