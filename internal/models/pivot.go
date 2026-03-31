// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "encoding/json"

type PivotResult struct {
	Success        bool              `json:"success"`
	Provider       string            `json:"provider"`
	Method         string            `json:"method"`
	Credentials    map[string]string `json:"credentials,omitempty"`
	RawCredentials map[string]string `json:"raw_credentials,omitempty"`
	Resources      []CloudResource   `json:"resources,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
	Duration       float64           `json:"duration_ms"`
}

type CloudResource struct {
	Type     string            `json:"type"`
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Region   string            `json:"region,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (r *PivotResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalPivotResult(data []byte) (*PivotResult, error) {
	var r PivotResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
