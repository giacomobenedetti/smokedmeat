// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "encoding/json"

type CloudQueryResult struct {
	Provider  string          `json:"provider"`
	QueryType string          `json:"query_type"`
	Success   bool            `json:"success"`
	Resources []CloudResource `json:"resources,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func (r *CloudQueryResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalCloudQueryResult(data []byte) (*CloudQueryResult, error) {
	var r CloudQueryResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
