// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package pass

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/nats"
)

// setupNATSContainer starts a NATS container with JetStream enabled.
func setupNATSContainer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()

	natsContainer, err := nats.Run(ctx, "nats:2.10-alpine")
	require.NoError(t, err)

	natsURL, err := natsContainer.ConnectionString(ctx)
	require.NoError(t, err)

	cleanup := func() {
		_ = natsContainer.Terminate(ctx)
	}

	return natsURL, cleanup
}

// =============================================================================
// Client Integration Tests
// =============================================================================

func TestClient_Integration_Connect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	assert.True(t, client.IsConnected())
	assert.NotNil(t, client.JetStream())
	assert.NotNil(t, client.Conn())
}

func TestClient_Integration_EnsureStream(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	// Create stream
	stream, err := client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)
	assert.NotNil(t, stream)

	// Verify stream exists
	info, err := stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, "SMOKEDMEAT", info.Config.Name)
	assert.Len(t, info.Config.Subjects, 3)
}

func TestClient_Integration_Close(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)

	assert.True(t, client.IsConnected())

	client.Close()

	assert.False(t, client.IsConnected())
}

// =============================================================================
// Publisher Integration Tests
// =============================================================================

func TestPublisher_Integration_Publish(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	publisher := NewPublisher(client)

	// Publish a message
	err = publisher.Publish(ctx, OrdersSubject("agent-1"), []byte(`{"test": "data"}`))
	require.NoError(t, err)
}

func TestPublisher_Integration_PublishOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	publisher := NewPublisher(client)

	// Publish order
	orderData := []byte(`{"order_id": "test-123", "command": "exec"}`)
	err = publisher.PublishOrder(ctx, "agent-1", orderData)
	require.NoError(t, err)
}

func TestPublisher_Integration_PublishColeslaw(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	publisher := NewPublisher(client)

	// Publish coleslaw
	coleslawData := []byte(`{"order_id": "test-123", "stdout": "result"}`)
	err = publisher.PublishColeslaw(ctx, "agent-1", coleslawData)
	require.NoError(t, err)
}

func TestPublisher_Integration_PublishBeacon(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	publisher := NewPublisher(client)

	// Publish beacon
	beaconData := []byte(`{"agent_id": "agent-1", "hostname": "test-host"}`)
	err = publisher.PublishBeacon(ctx, "agent-1", beaconData)
	require.NoError(t, err)
}

// =============================================================================
// Consumer Integration Tests
// =============================================================================

func TestConsumer_Integration_Consume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	// Create consumer
	consumer, err := NewConsumer(ctx, client, OrdersConsumerConfig("agent-1"))
	require.NoError(t, err)

	// Set up message receiver
	received := make(chan []byte, 1)
	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		received <- msg.Data()
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer cc.Stop()

	// Publish a message
	publisher := NewPublisher(client)
	err = publisher.PublishOrder(ctx, "agent-1", []byte(`{"test": "consume"}`))
	require.NoError(t, err)

	// Wait for message
	select {
	case data := <-received:
		var msg map[string]string
		require.NoError(t, json.Unmarshal(data, &msg))
		assert.Equal(t, "consume", msg["test"])
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestConsumer_Integration_ConsumeWithTimeout_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	consumer, err := NewConsumer(ctx, client, OrdersConsumerConfig("timeout-test"))
	require.NoError(t, err)

	received := make(chan []byte, 1)
	cc, err := consumer.ConsumeWithTimeout(5*time.Second, func(ctx context.Context, msg jetstream.Msg) {
		// Handler completes quickly
		received <- msg.Data()
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer cc.Stop()

	publisher := NewPublisher(client)
	err = publisher.PublishOrder(ctx, "timeout-test", []byte(`{"test": "timeout-success"}`))
	require.NoError(t, err)

	select {
	case data := <-received:
		var msg map[string]string
		require.NoError(t, json.Unmarshal(data, &msg))
		assert.Equal(t, "timeout-success", msg["test"])
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestConsumer_Integration_ConsumeWithTimeout_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	consumer, err := NewConsumer(ctx, client, OrdersConsumerConfig("timeout-fail"))
	require.NoError(t, err)

	handlerStarted := make(chan struct{})
	handlerCompleted := make(chan struct{})

	cc, err := consumer.ConsumeWithTimeout(100*time.Millisecond, func(ctx context.Context, msg jetstream.Msg) {
		close(handlerStarted)
		// Handler takes too long - should timeout
		select {
		case <-ctx.Done():
			// Context was cancelled due to timeout - expected
			close(handlerCompleted)
		case <-time.After(5 * time.Second):
			// Shouldn't reach here
		}
	})
	require.NoError(t, err)
	defer cc.Stop()

	publisher := NewPublisher(client)
	err = publisher.PublishOrder(ctx, "timeout-fail", []byte(`{"test": "timeout"}`))
	require.NoError(t, err)

	// Wait for handler to start
	select {
	case <-handlerStarted:
		// Good
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}

	// Wait for handler to detect timeout
	select {
	case <-handlerCompleted:
		// Handler properly detected context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("handler didn't detect timeout")
	}
}

func TestConsumer_Integration_Fetch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	// Publish messages first
	publisher := NewPublisher(client)
	for i := 0; i < 3; i++ {
		err = publisher.PublishOrder(ctx, "fetch-test", []byte(`{"index": `+string(rune('0'+i))+`}`))
		require.NoError(t, err)
	}

	// Create consumer and fetch
	consumer, err := NewConsumer(ctx, client, OrdersConsumerConfig("fetch-test"))
	require.NoError(t, err)

	fetchCtx, fetchCancel := context.WithTimeout(ctx, 5*time.Second)
	defer fetchCancel()

	batch, err := consumer.Fetch(fetchCtx, 10)
	require.NoError(t, err)

	// Count messages
	count := 0
	for msg := range batch.Messages() {
		count++
		_ = msg.Ack()
	}

	assert.Equal(t, 3, count)
}

func TestConsumer_Integration_Info(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	client, err := NewClient(ctx, DefaultConfig(natsURL))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	consumer, err := NewConsumer(ctx, client, OrdersConsumerConfig("info-test"))
	require.NoError(t, err)

	info, err := consumer.Info(ctx)
	require.NoError(t, err)

	assert.Equal(t, "orders-info-test", info.Name)
	assert.Equal(t, "smokedmeat.orders.info-test", info.Config.FilterSubject)
}

// =============================================================================
// End-to-End Flow Tests
// =============================================================================

func TestPass_Integration_PublishConsume_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	natsURL, cleanup := setupNATSContainer(t, ctx)
	defer cleanup()

	// Publisher client
	pubClient, err := NewClient(ctx, ClientConfig{
		URL:  natsURL,
		Name: "publisher",
	})
	require.NoError(t, err)
	defer pubClient.Close()

	_, err = pubClient.EnsureStream(ctx, DefaultStreamConfig())
	require.NoError(t, err)

	// Consumer client
	subClient, err := NewClient(ctx, ClientConfig{
		URL:  natsURL,
		Name: "subscriber",
	})
	require.NoError(t, err)
	defer subClient.Close()

	// Create consumers for all subject types
	ordersConsumer, err := NewConsumer(ctx, subClient, OrdersConsumerConfig("round-trip"))
	require.NoError(t, err)

	coleslawConsumer, err := NewConsumer(ctx, subClient, ColeslawConsumerConfig("round-trip"))
	require.NoError(t, err)

	beaconConsumer, err := NewConsumer(ctx, subClient, BeaconConsumerConfig("round-trip"))
	require.NoError(t, err)

	// Track received messages
	var mu sync.Mutex
	received := make(map[string][]byte)

	// Start consumers
	ordersCC, err := ordersConsumer.Consume(func(msg jetstream.Msg) {
		mu.Lock()
		received["order"] = msg.Data()
		mu.Unlock()
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer ordersCC.Stop()

	coleslawCC, err := coleslawConsumer.Consume(func(msg jetstream.Msg) {
		mu.Lock()
		received["coleslaw"] = msg.Data()
		mu.Unlock()
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer coleslawCC.Stop()

	beaconCC, err := beaconConsumer.Consume(func(msg jetstream.Msg) {
		mu.Lock()
		received["beacon"] = msg.Data()
		mu.Unlock()
		_ = msg.Ack()
	})
	require.NoError(t, err)
	defer beaconCC.Stop()

	// Publish to all subjects
	publisher := NewPublisher(pubClient)

	err = publisher.PublishOrder(ctx, "round-trip", []byte(`{"type": "order"}`))
	require.NoError(t, err)

	err = publisher.PublishColeslaw(ctx, "round-trip", []byte(`{"type": "coleslaw"}`))
	require.NoError(t, err)

	err = publisher.PublishBeacon(ctx, "round-trip", []byte(`{"type": "beacon"}`))
	require.NoError(t, err)

	// Wait for all messages
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		gotAll := len(received) == 3
		mu.Unlock()
		if gotAll {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()

	assert.Contains(t, string(received["order"]), "order")
	assert.Contains(t, string(received["coleslaw"]), "coleslaw")
	assert.Contains(t, string(received["beacon"]), "beacon")
}
