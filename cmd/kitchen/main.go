// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main implements the Kitchen C2 server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Print(buildinfo.String())
		return nil
	}

	printBanner()

	// Create context that cancels on interrupt
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Load configuration from environment
	config := kitchen.DefaultConfig()

	if port := os.Getenv("KITCHEN_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("invalid KITCHEN_PORT: %w", err)
		}
		config.Port = p
	}

	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		config.NatsURL = natsURL
	}

	if dbPath := os.Getenv("KITCHEN_DB_PATH"); dbPath != "" {
		config.DBPath = dbPath
	}

	// Auth configuration
	if keysPath := os.Getenv("AUTHORIZED_KEYS_PATH"); keysPath != "" {
		config.AuthorizedKeysPath = keysPath
	}
	if authMode := os.Getenv("AUTH_MODE"); authMode == "token" {
		config.AuthMode = kitchen.AuthModeToken
		config.AuthToken = os.Getenv("AUTH_TOKEN")
	}

	// Create and start server
	server := kitchen.New(config)
	return server.Start(ctx)
}

func printBanner() {
	fmt.Printf("SmokedMeat Kitchen %s - C2 Server\n", buildinfo.Version)
	fmt.Println("Copyright (C) 2026 boostsecurity.io")
	fmt.Println("Licensed under AGPL v3.0 - For authorized security testing only.")
	fmt.Println()
}
