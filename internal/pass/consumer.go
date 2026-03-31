// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pass

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// DefaultCallbackTimeout is the default timeout for consumer callbacks.
const DefaultCallbackTimeout = 30 * time.Second

// Consumer consumes messages from NATS JetStream subjects.
type Consumer struct {
	client   *Client
	stream   jetstream.Stream
	consumer jetstream.Consumer
}

// ConsumerConfig holds configuration for creating a consumer.
type ConsumerConfig struct {
	StreamName    string
	ConsumerName  string
	FilterSubject string
	Durable       bool
}

// NewConsumer creates a new Consumer for a given stream and subject filter.
func NewConsumer(ctx context.Context, client *Client, config ConsumerConfig) (*Consumer, error) {
	stream, err := client.js.Stream(ctx, config.StreamName)
	if err != nil {
		return nil, fmt.Errorf("failed to get stream %s: %w", config.StreamName, err)
	}

	consumerConfig := jetstream.ConsumerConfig{
		Name:          config.ConsumerName,
		FilterSubject: config.FilterSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    3,
	}

	if config.Durable {
		consumerConfig.Durable = config.ConsumerName
	}

	consumer, err := stream.CreateOrUpdateConsumer(ctx, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer %s: %w", config.ConsumerName, err)
	}

	return &Consumer{
		client:   client,
		stream:   stream,
		consumer: consumer,
	}, nil
}

// ConsumeWithTimeout starts consuming messages with a timeout-protected callback.
// If the handler doesn't complete within the timeout, the message is NAKed
// and an error is logged. This prevents hung callbacks from blocking the consumer.
func (c *Consumer) ConsumeWithTimeout(timeout time.Duration, handler func(ctx context.Context, msg jetstream.Msg)) (jetstream.ConsumeContext, error) {
	wrappedHandler := func(msg jetstream.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		done := make(chan struct{})
		go func() {
			handler(ctx, msg)
			close(done)
		}()

		select {
		case <-done:
			// Handler completed successfully
		case <-ctx.Done():
			// Timeout - NAK the message so it can be redelivered
			slog.Warn("consumer callback timed out",
				"subject", msg.Subject(),
				"timeout", timeout,
			)
			_ = msg.Nak()
		}
	}

	cc, err := c.consumer.Consume(wrappedHandler)
	if err != nil {
		return nil, fmt.Errorf("failed to start consumer: %w", err)
	}
	return cc, nil
}
