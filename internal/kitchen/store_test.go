// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestOrderStore_AddAndNext(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	order := models.NewOrder("session-1", "agent-1", "exec", []string{"ls", "-la"})
	err := store.Add(order)
	require.NoError(t, err)

	// Should get the order back
	got := store.Next("agent-1")
	require.NotNil(t, got)
	assert.Equal(t, order.OrderID, got.OrderID)

	// Should not get another order (only one pending)
	got = store.Next("agent-1")
	assert.Nil(t, got)
}

func TestOrderStore_FIFOOrdering(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	// Add 3 orders
	order1 := models.NewOrder("s", "agent-1", "exec", []string{"cmd1"})
	order2 := models.NewOrder("s", "agent-1", "exec", []string{"cmd2"})
	order3 := models.NewOrder("s", "agent-1", "exec", []string{"cmd3"})

	require.NoError(t, store.Add(order1))
	require.NoError(t, store.Add(order2))
	require.NoError(t, store.Add(order3))

	// Should come out in FIFO order
	got1 := store.Next("agent-1")
	require.NotNil(t, got1)
	assert.Equal(t, order1.OrderID, got1.OrderID)
	store.MarkDelivered(got1.OrderID)

	got2 := store.Next("agent-1")
	require.NotNil(t, got2)
	assert.Equal(t, order2.OrderID, got2.OrderID)
	store.MarkDelivered(got2.OrderID)

	got3 := store.Next("agent-1")
	require.NotNil(t, got3)
	assert.Equal(t, order3.OrderID, got3.OrderID)
}

func TestOrderStore_IsolatedAgents(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	orderA := models.NewOrder("s", "agent-A", "exec", []string{"for-A"})
	orderB := models.NewOrder("s", "agent-B", "exec", []string{"for-B"})

	require.NoError(t, store.Add(orderA))
	require.NoError(t, store.Add(orderB))

	// Each agent gets their own orders
	gotA := store.Next("agent-A")
	gotB := store.Next("agent-B")

	require.NotNil(t, gotA)
	require.NotNil(t, gotB)
	assert.Equal(t, orderA.OrderID, gotA.OrderID)
	assert.Equal(t, orderB.OrderID, gotB.OrderID)

	// No more orders for either
	assert.Nil(t, store.Next("agent-A"))
	assert.Nil(t, store.Next("agent-B"))
}

func TestOrderStore_QueueFull(t *testing.T) {
	config := DefaultOrderStoreConfig()
	config.MaxPendingPerAgent = 2
	store := NewOrderStore(config)

	order1 := models.NewOrder("s", "agent-1", "exec", []string{"1"})
	order2 := models.NewOrder("s", "agent-1", "exec", []string{"2"})
	order3 := models.NewOrder("s", "agent-1", "exec", []string{"3"})

	assert.NoError(t, store.Add(order1))
	assert.NoError(t, store.Add(order2))
	assert.ErrorIs(t, store.Add(order3), ErrQueueFull)

	// Different agent should still work
	orderOther := models.NewOrder("s", "agent-2", "exec", []string{"other"})
	assert.NoError(t, store.Add(orderOther))
}

func TestOrderStore_Deduplication(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	order := models.NewOrder("s", "agent-1", "exec", []string{"cmd"})

	// Add same order twice
	require.NoError(t, store.Add(order))
	require.NoError(t, store.Add(order)) // Should be silently ignored

	// Should only get one order
	got := store.Next("agent-1")
	require.NotNil(t, got)
	assert.Nil(t, store.Next("agent-1"))

}

func TestOrderStore_MarkDelivered(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	order := models.NewOrder("s", "agent-1", "exec", []string{})
	require.NoError(t, store.Add(order))

	got := store.Next("agent-1")
	require.NotNil(t, got)

	store.MarkDelivered(got.OrderID)
}

func TestOrderStore_MarkCompleted(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	order := models.NewOrder("s", "agent-1", "exec", []string{})
	require.NoError(t, store.Add(order))

	got := store.Next("agent-1")
	require.NotNil(t, got)
	store.MarkDelivered(got.OrderID)
	store.MarkCompleted(got.OrderID)
}

func TestOrderStore_MarkFailed(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	order := models.NewOrder("s", "agent-1", "exec", []string{})
	require.NoError(t, store.Add(order))

	got := store.Next("agent-1")
	require.NotNil(t, got)
	store.MarkDelivered(got.OrderID)
	store.MarkFailed(got.OrderID, "execution failed")
}

func TestOrderStore_ConcurrentAccess(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())
	agentID := "concurrent-agent"

	var wg sync.WaitGroup
	orderCount := 100
	delivered := 0
	var mu sync.Mutex

	// Producer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < orderCount; i++ {
			order := models.NewOrder("s", agentID, "exec", []string{})
			_ = store.Add(order)
		}
	}()

	// Consumer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			mu.Lock()
			if delivered >= orderCount {
				mu.Unlock()
				return
			}
			mu.Unlock()

			if order := store.Next(agentID); order != nil {
				store.MarkDelivered(order.OrderID)
				store.MarkCompleted(order.OrderID)
				mu.Lock()
				delivered++
				mu.Unlock()
			} else {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	wg.Wait()
	assert.Equal(t, orderCount, delivered)
}

func TestOrderStore_Cleanup_ExpiredOrders(t *testing.T) {
	config := DefaultOrderStoreConfig()
	config.OrderTTL = 50 * time.Millisecond
	store := NewOrderStore(config)

	order := models.NewOrder("s", "agent-1", "exec", []string{})
	require.NoError(t, store.Add(order))

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	cleaned := store.Cleanup()
	assert.Equal(t, 1, cleaned)
}

func TestOrderStore_Cleanup_ExpiredInflight(t *testing.T) {
	config := DefaultOrderStoreConfig()
	config.InflightTimeout = 50 * time.Millisecond
	store := NewOrderStore(config)

	order := models.NewOrder("s", "agent-1", "exec", []string{})
	require.NoError(t, store.Add(order))

	got := store.Next("agent-1")
	require.NotNil(t, got)
	store.MarkDelivered(got.OrderID)

	// Wait for inflight timeout
	time.Sleep(100 * time.Millisecond)

	cleaned := store.Cleanup()
	assert.Equal(t, 1, cleaned)
}

func TestOrderStore_StartCleanup_StopsOnContextCancel(t *testing.T) {
	config := DefaultOrderStoreConfig()
	config.CleanupInterval = 10 * time.Millisecond
	store := NewOrderStore(config)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		store.StartCleanup(ctx)
		close(done)
	}()

	// Let it run a few cycles
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case <-done:
		// Success - goroutine exited
	case <-time.After(time.Second):
		t.Fatal("StartCleanup did not stop after context cancel")
	}
}

func TestOrderStore_NextReturnsNilForUnknownAgent(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	got := store.Next("unknown-agent")
	assert.Nil(t, got)
}

func TestOrderStore_MarkOperationsOnNonexistentOrder(t *testing.T) {
	store := NewOrderStore(DefaultOrderStoreConfig())

	// These should not panic or cause issues
	store.MarkDelivered("nonexistent")
	store.MarkCompleted("nonexistent")
	store.MarkFailed("nonexistent", "reason")
}
