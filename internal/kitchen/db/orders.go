// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"sort"

	bolt "go.etcd.io/bbolt"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

// OrderRepository provides database operations for orders.
type OrderRepository struct {
	db *DB
}

// NewOrderRepository creates a new OrderRepository.
func NewOrderRepository(db *DB) *OrderRepository {
	return &OrderRepository{db: db}
}

// ListPending retrieves all pending orders across all agents.
func (r *OrderRepository) ListPending() ([]*models.Order, error) {
	var orders []*models.Order

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketOrders)

		return b.ForEach(func(k, v []byte) error {
			var order models.Order
			if err := json.Unmarshal(v, &order); err != nil {
				return err
			}

			if order.Status == models.OrderStatusPending {
				orders = append(orders, &order)
			}
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by CreatedAt ascending
	sort.Slice(orders, func(i, j int) bool {
		return orders[i].CreatedAt.Before(orders[j].CreatedAt)
	})

	return orders, nil
}
