// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestLootRepository_UpsertReplacesSameOriginSlot(t *testing.T) {
	db := setupDB(t)
	repo := NewLootRepository(db)

	first := &LootRow{
		SessionID:  "sess-1",
		AgentID:    "agt-old",
		Name:       "GOOGLE_APPLICATION_CREDENTIALS",
		Value:      "/tmp/old.json",
		Repository: "whooli/xyz",
		Workflow:   ".github/workflows/oidc-test.yml",
		Job:        "process",
		Timestamp:  time.Now().Add(-time.Minute),
	}
	second := &LootRow{
		SessionID:  "sess-2",
		AgentID:    "agt-new",
		Name:       "GOOGLE_APPLICATION_CREDENTIALS",
		Value:      "/tmp/new.json",
		Repository: "whooli/xyz",
		Workflow:   ".github/workflows/oidc-test.yml",
		Job:        "process",
		Timestamp:  time.Now(),
	}

	require.NoError(t, repo.Upsert(first))
	require.NoError(t, repo.Upsert(second))

	rows, err := repo.List()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "/tmp/new.json", rows[0].Value)
	assert.Equal(t, "agt-new", rows[0].AgentID)
}

func TestLootRepository_ListDedupesLegacyRowsByOrigin(t *testing.T) {
	db := setupDB(t)

	older := &LootRow{
		ID:         "legacy:sess-1:agt-old:GOOGLE_APPLICATION_CREDENTIALS",
		SessionID:  "sess-1",
		AgentID:    "agt-old",
		Name:       "GOOGLE_APPLICATION_CREDENTIALS",
		Value:      "/tmp/old.json",
		Repository: "whooli/xyz",
		Workflow:   ".github/workflows/oidc-test.yml",
		Job:        "process",
		Timestamp:  time.Now().Add(-2 * time.Minute),
	}
	newer := &LootRow{
		ID:         "legacy:sess-2:agt-new:GOOGLE_APPLICATION_CREDENTIALS",
		SessionID:  "sess-2",
		AgentID:    "agt-new",
		Name:       "GOOGLE_APPLICATION_CREDENTIALS",
		Value:      "/tmp/new.json",
		Repository: "whooli/xyz",
		Workflow:   ".github/workflows/oidc-test.yml",
		Job:        "process",
		Timestamp:  time.Now(),
	}

	require.NoError(t, db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketLoot)
		for _, row := range []*LootRow{older, newer} {
			data, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(row.ID), data); err != nil {
				return err
			}
		}
		return nil
	}))

	rows, err := NewLootRepository(db).List()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "/tmp/new.json", rows[0].Value)
}
