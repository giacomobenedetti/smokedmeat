// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pass

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

// Publisher publishes messages to NATS JetStream subjects.
type Publisher struct {
	client *Client
}

// NewPublisher creates a new Publisher.
func NewPublisher(client *Client) *Publisher {
	return &Publisher{client: client}
}

// Publish publishes a message to the given subject.
func (p *Publisher) Publish(ctx context.Context, subject string, data []byte) error {
	ack, err := p.client.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish to %s: %w", subject, err)
	}
	_ = ack // Could log or track the ack if needed
	return nil
}

// PublishAsync publishes a message asynchronously.
func (p *Publisher) PublishAsync(subject string, data []byte) (jetstream.PubAckFuture, error) {
	future, err := p.client.js.PublishAsync(subject, data)
	if err != nil {
		return nil, fmt.Errorf("failed to publish async to %s: %w", subject, err)
	}
	return future, nil
}

// PublishOrder publishes an order to a specific agent.
func (p *Publisher) PublishOrder(ctx context.Context, agentID string, data []byte) error {
	return p.Publish(ctx, OrdersSubject(agentID), data)
}

// PublishColeslaw publishes a response from a specific agent.
func (p *Publisher) PublishColeslaw(ctx context.Context, agentID string, data []byte) error {
	return p.Publish(ctx, ColeslawSubject(agentID), data)
}

// PublishBeacon publishes a heartbeat from a specific agent.
func (p *Publisher) PublishBeacon(ctx context.Context, agentID string, data []byte) error {
	return p.Publish(ctx, BeaconSubject(agentID), data)
}
