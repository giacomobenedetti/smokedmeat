// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

var (
	// ErrQueueFull is returned when an agent's order queue is at capacity.
	ErrQueueFull = errors.New("order queue full for agent")

	// ErrOrderNotFound is returned when an order ID doesn't exist.
	ErrOrderNotFound = errors.New("order not found")
)

// OrderStoreConfig holds configuration for the order store.
type OrderStoreConfig struct {
	// MaxPendingPerAgent limits queue depth per agent (0 = unlimited).
	MaxPendingPerAgent int

	// OrderTTL is how long to keep undelivered orders (0 = forever).
	OrderTTL time.Duration

	// InflightTimeout is how long to wait for completion before cleanup.
	InflightTimeout time.Duration

	// CleanupInterval is how often to run the cleanup routine.
	CleanupInterval time.Duration
}

// DefaultOrderStoreConfig returns sensible defaults.
func DefaultOrderStoreConfig() OrderStoreConfig {
	return OrderStoreConfig{
		MaxPendingPerAgent: 100,
		OrderTTL:           1 * time.Hour,
		InflightTimeout:    5 * time.Minute,
		CleanupInterval:    1 * time.Minute,
	}
}

// OrderStore holds pending orders for agent delivery.
// Thread-safe for concurrent access from consumer goroutine and HTTP handlers.
type OrderStore struct {
	mu     sync.RWMutex
	config OrderStoreConfig

	// pending maps agent_id -> queue of orders awaiting delivery (FIFO)
	pending map[string][]*models.Order

	// inflight maps order_id -> order (delivered but not yet completed)
	inflight map[string]*models.Order

	// seen tracks order IDs to prevent duplicates
	seen map[string]time.Time

	// metrics
	totalReceived  int64
	totalDelivered int64
	totalCompleted int64
	totalFailed    int64
}

// NewOrderStore creates an initialized OrderStore.
func NewOrderStore(config OrderStoreConfig) *OrderStore {
	return &OrderStore{
		config:   config,
		pending:  make(map[string][]*models.Order),
		inflight: make(map[string]*models.Order),
		seen:     make(map[string]time.Time),
	}
}

// Add queues an order for the specified agent.
// Returns error if queue is full (based on MaxPendingPerAgent).
func (s *OrderStore) Add(order *models.Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.seen[order.OrderID]; exists {
		return nil // dedupe
	}

	if s.config.MaxPendingPerAgent > 0 {
		if len(s.pending[order.AgentID]) >= s.config.MaxPendingPerAgent {
			return ErrQueueFull
		}
	}

	s.pending[order.AgentID] = append(s.pending[order.AgentID], order)
	s.seen[order.OrderID] = time.Now()
	s.totalReceived++

	return nil
}

// Next returns the next pending order for an agent, or nil if none.
// Moves the order from pending to inflight.
func (s *OrderStore) Next(agentID string) *models.Order {
	s.mu.Lock()
	defer s.mu.Unlock()

	queue := s.pending[agentID]
	if len(queue) == 0 {
		return nil
	}

	order := queue[0]
	s.pending[agentID] = queue[1:]

	if len(s.pending[agentID]) == 0 {
		delete(s.pending, agentID)
	}

	s.inflight[order.OrderID] = order

	return order
}

// MarkDelivered confirms HTTP delivery was successful.
// Updates metrics. Order stays in inflight for completion tracking.
func (s *OrderStore) MarkDelivered(orderID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.inflight[orderID]; exists {
		s.totalDelivered++
	}
}

// MarkCompleted marks an order as successfully completed.
// Removes from inflight.
func (s *OrderStore) MarkCompleted(orderID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.inflight[orderID]; exists {
		delete(s.inflight, orderID)
		s.totalCompleted++
	}
}

// MarkFailed marks an order as failed.
// Removes from inflight.
func (s *OrderStore) MarkFailed(orderID, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.inflight[orderID]; exists {
		delete(s.inflight, orderID)
		s.totalFailed++
	}
}

// Cleanup removes stale orders based on TTL and inflight timeout.
func (s *OrderStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cleaned := 0

	if s.config.OrderTTL > 0 {
		for agentID, queue := range s.pending {
			var kept []*models.Order
			for _, order := range queue {
				if now.Sub(order.CreatedAt) < s.config.OrderTTL {
					kept = append(kept, order)
				} else {
					cleaned++
				}
			}
			if len(kept) > 0 {
				s.pending[agentID] = kept
			} else {
				delete(s.pending, agentID)
			}
		}
	}

	if s.config.InflightTimeout > 0 {
		for orderID, order := range s.inflight {
			if now.Sub(order.UpdatedAt) > s.config.InflightTimeout {
				delete(s.inflight, orderID)
				s.totalFailed++
				cleaned++
			}
		}
	}

	seenTTL := s.config.OrderTTL
	if seenTTL == 0 {
		seenTTL = 24 * time.Hour
	}
	for orderID, seenAt := range s.seen {
		if now.Sub(seenAt) > seenTTL {
			delete(s.seen, orderID)
		}
	}

	return cleaned
}

// StartCleanup starts a background goroutine that periodically cleans up stale orders.
// Stops when the context is canceled.
func (s *OrderStore) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Cleanup()
		}
	}
}
