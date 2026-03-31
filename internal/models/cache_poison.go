// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

type CachePoisonStatus struct {
	Status              string `json:"status"`
	Error               string `json:"error,omitempty"`
	RuntimeSource       string `json:"runtime_source,omitempty"`
	RuntimeTokenSummary string `json:"runtime_token_summary,omitempty"`
	ResultsURLSummary   string `json:"results_url_summary,omitempty"`
	CacheURLSummary     string `json:"cache_url_summary,omitempty"`
	Key                 string `json:"key,omitempty"`
	Version             string `json:"version,omitempty"`
	ArchiveSize         int64  `json:"archive_size,omitempty"`
}
