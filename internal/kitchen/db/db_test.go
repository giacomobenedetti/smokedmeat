// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "test.db")})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpen(t *testing.T) {
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "test.db"), CreateDir: true})
	require.NoError(t, err)
	defer db.Close()

	assert.NotNil(t, db)
}

func TestClose(t *testing.T) {
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "test.db")})
	require.NoError(t, err)

	err = db.Close()
	assert.NoError(t, err)
}

func TestOrderRepository_ListPending(t *testing.T) {
	db := setupDB(t)
	repo := NewOrderRepository(db)

	orders, err := repo.ListPending()
	require.NoError(t, err)
	assert.Empty(t, orders)
}
