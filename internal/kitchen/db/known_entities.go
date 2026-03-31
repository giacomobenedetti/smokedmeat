// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

type EntityType string

const (
	EntityTypeRepo EntityType = "repo"
	EntityTypeOrg  EntityType = "org"
)

type KnownEntityRow struct {
	ID            string     `json:"id"`
	EntityType    EntityType `json:"entity_type"`
	Name          string     `json:"name"`
	SessionID     string     `json:"session_id"`
	DiscoveredAt  time.Time  `json:"discovered_at"`
	DiscoveredVia string     `json:"discovered_via"`
	IsPrivate     bool       `json:"is_private"`
	Permissions   []string   `json:"permissions,omitempty"`
	SSHPermission string     `json:"ssh_permission,omitempty"`
}

type KnownEntityRepository struct {
	db *DB
}

func NewKnownEntityRepository(db *DB) *KnownEntityRepository {
	return &KnownEntityRepository{db: db}
}

func (r *KnownEntityRepository) Upsert(entity *KnownEntityRow) error {
	if entity.DiscoveredAt.IsZero() {
		entity.DiscoveredAt = time.Now()
	}

	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketKnownEntities)

		existing := b.Get([]byte(entity.ID))
		if existing != nil {
			var old KnownEntityRow
			if err := json.Unmarshal(existing, &old); err == nil {
				entity.DiscoveredAt = old.DiscoveredAt
			}
		}

		data, err := json.Marshal(entity)
		if err != nil {
			return fmt.Errorf("failed to marshal known entity: %w", err)
		}

		return b.Put([]byte(entity.ID), data)
	})
}

func (r *KnownEntityRepository) ListBySession(sessionID string) ([]*KnownEntityRow, error) {
	var entities []*KnownEntityRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketKnownEntities)

		return b.ForEach(func(k, v []byte) error {
			var entity KnownEntityRow
			if err := json.Unmarshal(v, &entity); err != nil {
				return err
			}

			if entity.SessionID == sessionID {
				entities = append(entities, &entity)
			}
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(entities, func(i, j int) bool {
		return entities[i].DiscoveredAt.After(entities[j].DiscoveredAt)
	})

	return entities, nil
}

func (r *KnownEntityRepository) ListRepos(sessionID string) ([]*KnownEntityRow, error) {
	entities, err := r.ListBySession(sessionID)
	if err != nil {
		return nil, err
	}

	var repos []*KnownEntityRow
	for _, e := range entities {
		if e.EntityType == EntityTypeRepo {
			repos = append(repos, e)
		}
	}

	return repos, nil
}

func (r *KnownEntityRepository) ListOrgs(sessionID string) ([]*KnownEntityRow, error) {
	entities, err := r.ListBySession(sessionID)
	if err != nil {
		return nil, err
	}

	var orgs []*KnownEntityRow
	for _, e := range entities {
		if e.EntityType == EntityTypeOrg {
			orgs = append(orgs, e)
		}
	}

	return orgs, nil
}
