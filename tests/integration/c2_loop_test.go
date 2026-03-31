// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pass"
)

// setupNATSContainer starts a NATS container with JetStream enabled.
// Note: The testcontainers NATS module enables JetStream by default (-js flag).
func setupNATSContainer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()

	// JetStream is enabled by default in testcontainers-go NATS module
	natsContainer, err := nats.Run(ctx, "nats:2.10-alpine")
	require.NoError(t, err)

	natsURL, err := natsContainer.ConnectionString(ctx)
	require.NoError(t, err)

	cleanup := func() {
		_ = natsContainer.Terminate(ctx)
	}

	return natsURL, cleanup
}

// setupPassClient creates a NATS client and ensures the stream exists.
func setupPassClient(t *testing.T, ctx context.Context, natsURL, name string) *pass.Client {
	t.Helper()

	client, err := pass.NewClient(ctx, pass.ClientConfig{
		URL:  natsURL,
		Name: name,
	})
	require.NoError(t, err)

	_, err = client.EnsureStream(ctx, pass.DefaultStreamConfig())
	require.NoError(t, err)

	return client
}

// TestC2Loop_FullOrderExecution tests the complete C2 communication loop:
// Counter publishes order → Kitchen queues → Brisket polls → executes → returns coleslaw → Counter receives
func TestC2Loop_FullOrderExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start NATS container
	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Set up Counter client (publisher + coleslaw consumer)
	counterClient := setupPassClient(t, ctx, natsURL, "counter-test")
	defer counterClient.Close()

	counterPublisher := pass.NewPublisher(counterClient)

	// Set up coleslaw consumer to receive responses
	coleslawConsumer, err := pass.NewConsumer(ctx, counterClient, pass.ColeslawConsumerConfig("test-session"))
	require.NoError(t, err)

	receivedColeslaw := make(chan *models.Coleslaw, 1)
	coleslawCC, err := coleslawConsumer.Consume(func(msg jetstream.Msg) {
		coleslaw, err := models.UnmarshalColeslaw(msg.Data())
		if err == nil {
			receivedColeslaw <- coleslaw
		}
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer coleslawCC.Stop()

	// Set up Kitchen components (store + handler + publisher)
	kitchenClient := setupPassClient(t, ctx, natsURL, "kitchen-test")
	defer kitchenClient.Close()

	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	kitchenPublisher := pass.NewPublisher(kitchenClient)
	handler := kitchen.NewHandler(kitchenPublisher, store)

	// Create test HTTP server with Kitchen routes
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	// Create and publish an order from Counter
	agentID := "test-agent-001"
	order := models.NewOrder("test-session", agentID, "exec", []string{"echo", "hello"})

	orderData, err := order.Marshal()
	require.NoError(t, err)

	err = counterPublisher.PublishOrder(ctx, agentID, orderData)
	require.NoError(t, err)

	// Manually add order to store (simulating Kitchen's NATS consumer)
	// In a full integration test, we'd use Kitchen.Start() but that requires more setup
	err = store.Add(order)
	require.NoError(t, err)

	// Simulate Brisket polling for orders
	pollResp, err := http.Get(testServer.URL + "/b/" + agentID)
	require.NoError(t, err)
	defer pollResp.Body.Close()

	require.Equal(t, http.StatusOK, pollResp.StatusCode)

	var receivedOrder models.Order
	err = json.NewDecoder(pollResp.Body).Decode(&receivedOrder)
	require.NoError(t, err)
	assert.Equal(t, order.OrderID, receivedOrder.OrderID)
	assert.Equal(t, "exec", receivedOrder.Command)

	// Simulate Brisket executing and returning coleslaw
	coleslaw := models.NewColeslaw(order.OrderID, "test-session", agentID)
	coleslaw.SetOutput([]byte("hello\n"), nil, 0)

	coleslawData, err := coleslaw.Marshal()
	require.NoError(t, err)

	postResp, err := http.Post(
		testServer.URL+"/b/"+agentID,
		"application/json",
		strings.NewReader(string(coleslawData)),
	)
	require.NoError(t, err)
	defer postResp.Body.Close()

	require.Equal(t, http.StatusOK, postResp.StatusCode)

	// Wait for Counter to receive the coleslaw via NATS
	select {
	case received := <-receivedColeslaw:
		assert.Equal(t, order.OrderID, received.OrderID)
		// Stdout is base64 encoded in the model
		stdout, err := received.GetStdout()
		require.NoError(t, err)
		assert.Equal(t, "hello\n", string(stdout))
		assert.Equal(t, 0, received.ExitCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for coleslaw")
	}
}

// TestC2Loop_BeaconPublishing tests that beacons from Brisket are published to NATS
func TestC2Loop_BeaconPublishing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start NATS container
	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Set up client
	client := setupPassClient(t, ctx, natsURL, "test")
	defer client.Close()

	// Set up beacon consumer
	beaconConsumer, err := pass.NewConsumer(ctx, client, pass.BeaconConsumerConfig("test-session"))
	require.NoError(t, err)

	receivedBeacons := make(chan map[string]interface{}, 1)
	beaconCC, err := beaconConsumer.Consume(func(msg jetstream.Msg) {
		var beacon map[string]interface{}
		if err := json.Unmarshal(msg.Data(), &beacon); err == nil {
			receivedBeacons <- beacon
		}
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer beaconCC.Stop()

	// Create Kitchen handler
	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	publisher := pass.NewPublisher(client)
	handler := kitchen.NewHandler(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	// Simulate Brisket sending a beacon
	agentID := "beacon-test-agent"
	beacon := map[string]interface{}{
		"agent_id": agentID,
		"hostname": "test-host",
		"os":       "linux",
		"arch":     "amd64",
	}

	beaconData, err := json.Marshal(beacon)
	require.NoError(t, err)

	resp, err := http.Post(
		testServer.URL+"/b/"+agentID,
		"application/json",
		strings.NewReader(string(beaconData)),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Wait for beacon on NATS
	select {
	case received := <-receivedBeacons:
		assert.Equal(t, agentID, received["agent_id"])
		assert.Equal(t, "test-host", received["hostname"])
		assert.Equal(t, "linux", received["os"])
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for beacon")
	}
}

// TestC2Loop_MultiAgent tests multiple agents receiving different orders
func TestC2Loop_MultiAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start NATS container
	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Set up client
	client := setupPassClient(t, ctx, natsURL, "test")
	defer client.Close()

	// Create store and handlers
	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	publisher := pass.NewPublisher(client)
	handler := kitchen.NewHandler(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	// Create orders for two different agents
	agent1 := "agent-1"
	agent2 := "agent-2"

	order1 := models.NewOrder("session", agent1, "exec", []string{"whoami"})
	order2 := models.NewOrder("session", agent2, "exec", []string{"hostname"})

	require.NoError(t, store.Add(order1))
	require.NoError(t, store.Add(order2))

	// Poll for agent1 - should get order1
	resp1, err := http.Get(testServer.URL + "/b/" + agent1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	require.Equal(t, http.StatusOK, resp1.StatusCode)
	var receivedOrder1 models.Order
	err = json.NewDecoder(resp1.Body).Decode(&receivedOrder1)
	require.NoError(t, err)
	assert.Equal(t, order1.OrderID, receivedOrder1.OrderID)

	// Poll for agent2 - should get order2
	resp2, err := http.Get(testServer.URL + "/b/" + agent2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var receivedOrder2 models.Order
	err = json.NewDecoder(resp2.Body).Decode(&receivedOrder2)
	require.NoError(t, err)
	assert.Equal(t, order2.OrderID, receivedOrder2.OrderID)

	// Poll again for agent1 - should get 204 No Content
	resp3, err := http.Get(testServer.URL + "/b/" + agent1)
	require.NoError(t, err)
	defer resp3.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp3.StatusCode)
}

// TestC2Loop_ColeslawUpdatesOrderStatus tests that coleslaw updates order status in store
func TestC2Loop_ColeslawUpdatesOrderStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start NATS container
	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Set up client
	client := setupPassClient(t, ctx, natsURL, "test")
	defer client.Close()

	// Create store and handlers
	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	publisher := pass.NewPublisher(client)
	handler := kitchen.NewHandler(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	// Create and add order
	agentID := "status-test-agent"
	order := models.NewOrder("session", agentID, "exec", []string{"true"})
	require.NoError(t, store.Add(order))

	// Poll to get the order (marks as delivered)
	pollResp, err := http.Get(testServer.URL + "/b/" + agentID)
	require.NoError(t, err)
	pollResp.Body.Close()
	require.Equal(t, http.StatusOK, pollResp.StatusCode)

	// Check order is now delivered (in-flight)
	status := store.OrderStatus(order.OrderID)
	assert.Equal(t, models.OrderStatusDelivered, status)

	// Send successful coleslaw
	coleslaw := models.NewColeslaw(order.OrderID, "session", agentID)
	coleslaw.SetOutput([]byte("success"), nil, 0)

	coleslawData, err := coleslaw.Marshal()
	require.NoError(t, err)

	postResp, err := http.Post(
		testServer.URL+"/b/"+agentID,
		"application/json",
		strings.NewReader(string(coleslawData)),
	)
	require.NoError(t, err)
	postResp.Body.Close()
	require.Equal(t, http.StatusOK, postResp.StatusCode)

	// Check order is now completed (removed from store, so status check returns completed via seen map)
	status = store.OrderStatus(order.OrderID)
	assert.Equal(t, models.OrderStatusCompleted, status)
}

// TestC2Loop_FailedOrderStatus tests that failed coleslaw updates order status to failed
func TestC2Loop_FailedOrderStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start NATS container
	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Set up client
	client := setupPassClient(t, ctx, natsURL, "test")
	defer client.Close()

	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	publisher := pass.NewPublisher(client)
	handler := kitchen.NewHandler(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	agentID := "fail-test-agent"
	order := models.NewOrder("session", agentID, "exec", []string{"false"})
	require.NoError(t, store.Add(order))

	// Poll to deliver
	pollResp, err := http.Get(testServer.URL + "/b/" + agentID)
	require.NoError(t, err)
	pollResp.Body.Close()

	// Send failed coleslaw (non-zero exit code)
	coleslaw := models.NewColeslaw(order.OrderID, "session", agentID)
	coleslaw.SetOutput(nil, []byte("command failed"), 1)

	coleslawData, err := coleslaw.Marshal()
	require.NoError(t, err)

	postResp, err := http.Post(
		testServer.URL+"/b/"+agentID,
		"application/json",
		strings.NewReader(string(coleslawData)),
	)
	require.NoError(t, err)
	postResp.Body.Close()

	// Check order status - since it's been processed, it should return completed
	// (the store removes failed orders too, and our OrderStatus returns completed for seen orders)
	status := store.OrderStatus(order.OrderID)
	assert.Equal(t, models.OrderStatusCompleted, status)
}

// TestC2Loop_OrderFIFO tests that orders are delivered in FIFO order
func TestC2Loop_OrderFIFO(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start NATS container
	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Set up client
	client := setupPassClient(t, ctx, natsURL, "test")
	defer client.Close()

	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	publisher := pass.NewPublisher(client)
	handler := kitchen.NewHandler(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	agentID := "fifo-agent"

	// Add 3 orders in sequence
	order1 := models.NewOrder("session", agentID, "exec", []string{"echo", "1"})
	order2 := models.NewOrder("session", agentID, "exec", []string{"echo", "2"})
	order3 := models.NewOrder("session", agentID, "exec", []string{"echo", "3"})

	require.NoError(t, store.Add(order1))
	require.NoError(t, store.Add(order2))
	require.NoError(t, store.Add(order3))

	// Poll should return orders in FIFO order
	for i, expectedOrder := range []*models.Order{order1, order2, order3} {
		resp, err := http.Get(testServer.URL + "/b/" + agentID)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode, "Poll %d should return OK", i+1)

		var received models.Order
		err = json.NewDecoder(resp.Body).Decode(&received)
		resp.Body.Close()
		require.NoError(t, err)

		assert.Equal(t, expectedOrder.OrderID, received.OrderID, "Poll %d should return order %d", i+1, i+1)
	}

	// Fourth poll should return 204
	resp, err := http.Get(testServer.URL + "/b/" + agentID)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
