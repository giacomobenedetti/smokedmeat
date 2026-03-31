// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

var pantryKey = []byte("graph")

// SavePantry persists the attack graph to the database.
func (db *DB) SavePantry(p *pantry.Pantry) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketPantry)
		return b.Put(pantryKey, data)
	})
}

// LoadPantry retrieves the attack graph from the database.
// Returns nil if no graph is stored.
func (db *DB) LoadPantry() (*pantry.Pantry, error) {
	var data []byte

	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketPantry)
		data = b.Get(pantryKey)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, nil
	}

	p := pantry.New()
	if err := json.Unmarshal(data, p); err != nil {
		return nil, err
	}

	return p, nil
}
