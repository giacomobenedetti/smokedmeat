// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package db provides BBolt persistence for Kitchen state.
package db

import (
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// Bucket names
var (
	BucketOrders        = []byte("orders")
	BucketAgents        = []byte("agents")
	BucketSessions      = []byte("sessions")
	BucketStagers       = []byte("stagers")
	BucketMetrics       = []byte("metrics")
	BucketPantry        = []byte("pantry")
	BucketHistory       = []byte("history")
	BucketKnownEntities = []byte("known_entities")
	BucketLoot          = []byte("loot")
)

// DB wraps a BBolt database connection for Kitchen persistence.
type DB struct {
	bolt *bolt.DB
	path string
}

// Config holds database configuration.
type Config struct {
	// Path is the path to the BBolt database file.
	Path string

	// CreateDir creates the parent directory if it doesn't exist.
	CreateDir bool
}

// Open opens or creates a BBolt database.
func Open(config Config) (*DB, error) {
	if config.CreateDir {
		dir := filepath.Dir(config.Path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("failed to create database directory: %w", err)
			}
		}
	}

	boltDB, err := bolt.Open(config.Path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{
		bolt: boltDB,
		path: config.Path,
	}

	if err := db.createBuckets(); err != nil {
		boltDB.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	if db.bolt != nil {
		return db.bolt.Close()
	}
	return nil
}

// createBuckets creates all required buckets.
func (db *DB) createBuckets() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{
			BucketOrders,
			BucketAgents,
			BucketSessions,
			BucketStagers,
			BucketMetrics,
			BucketPantry,
			BucketHistory,
			BucketKnownEntities,
			BucketLoot,
		}

		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
			}
		}

		return nil
	})
}
