// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"context"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
)

type PrepareCachePoisonRequest struct {
	SessionID        string                      `json:"session_id"`
	ExternalURL      string                      `json:"external_url"`
	WriterStagerID   string                      `json:"writer_stager_id"`
	WriterRepository string                      `json:"writer_repository"`
	WriterWorkflow   string                      `json:"writer_workflow"`
	WriterJob        string                      `json:"writer_job"`
	Victim           cachepoison.VictimCandidate `json:"victim"`
	VictimDwellTime  string                      `json:"victim_dwell_time,omitempty"`
	PurgeToken       string                      `json:"purge_token,omitempty"`
	PurgeKey         string                      `json:"purge_key,omitempty"`
	PurgeKeyPrefix   string                      `json:"purge_key_prefix,omitempty"`
	PurgeRef         string                      `json:"purge_ref,omitempty"`
}

type PrepareCachePoisonResponse struct {
	VictimCallback   CallbackPayload `json:"victim_callback"`
	WriterCallback   CallbackPayload `json:"writer_callback"`
	VictimStagerID   string          `json:"victim_stager_id"`
	VictimStagerURL  string          `json:"victim_stager_url"`
	PurgedCacheCount int             `json:"purged_cache_count,omitempty"`
	PurgedKey        string          `json:"purged_key,omitempty"`
	PurgedCacheRef   string          `json:"purged_cache_ref,omitempty"`
	PurgedKeyPrefix  string          `json:"purged_key_prefix,omitempty"`
	Error            string          `json:"error,omitempty"`
}

func (k *KitchenClient) PrepareCachePoisonDeployment(ctx context.Context, req PrepareCachePoisonRequest) (*PrepareCachePoisonResponse, error) {
	var resp PrepareCachePoisonResponse
	err := k.doPostJSON(ctx, "/cache-poison/prepare", req, &resp, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
