// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package counter provides SSH agent-based authentication for the Counter TUI.
package counter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// ErrNoSSHAgent indicates SSH_AUTH_SOCK is not set.
	ErrNoSSHAgent = errors.New("SSH_AUTH_SOCK not set - is ssh-agent running?")

	// ErrNoKeysInAgent indicates the SSH agent has no keys.
	ErrNoKeysInAgent = errors.New("no keys found in SSH agent")

	// ErrKeyNotFound indicates the specified key was not found in the agent.
	ErrKeyNotFound = errors.New("specified key not found in SSH agent")

	// ErrAuthFailed indicates authentication failed.
	ErrAuthFailed = errors.New("authentication failed")
)

// SSHAuthClient handles SSH challenge-response authentication with Kitchen.
type SSHAuthClient struct {
	kitchenURL string
	operator   string
	keyComment string // Optional: filter keys by comment
	httpClient *http.Client
}

// SSHAuthConfig holds configuration for SSH authentication.
type SSHAuthConfig struct {
	// KitchenURL is the Kitchen server URL (e.g., "https://kitchen.example.com")
	KitchenURL string

	// Operator is the operator name (must match authorized_keys on Kitchen)
	Operator string

	// KeyComment optionally filters which SSH key to use by its comment
	KeyComment string
}

// NewSSHAuthClient creates a new SSH authentication client.
func NewSSHAuthClient(config SSHAuthConfig) *SSHAuthClient {
	return &SSHAuthClient{
		kitchenURL: strings.TrimSuffix(config.KitchenURL, "/"),
		operator:   config.Operator,
		keyComment: config.KeyComment,
		httpClient: &http.Client{},
	}
}

// Authenticate performs SSH challenge-response authentication and returns a session token.
// This is designed to work with SSH agents like Secretive on macOS.
func (c *SSHAuthClient) Authenticate() (string, error) {
	// Connect to SSH agent
	agentConn, err := connectToSSHAgent()
	if err != nil {
		return "", err
	}
	defer agentConn.Close()

	sshAgent := agent.NewClient(agentConn)

	// List keys from agent
	keys, err := sshAgent.List()
	if err != nil {
		return "", fmt.Errorf("failed to list keys from SSH agent: %w", err)
	}

	if len(keys) == 0 {
		return "", ErrNoKeysInAgent
	}

	// Find the key to use
	key, err := c.findKey(keys)
	if err != nil {
		return "", err
	}

	// Calculate fingerprint
	fingerprint := ssh.FingerprintSHA256(key)

	// Step 1: Request challenge from Kitchen
	nonce, err := c.requestChallenge(fingerprint)
	if err != nil {
		return "", err
	}

	// Step 2: Sign the nonce with SSH agent
	signature, err := sshAgent.Sign(key, nonce)
	if err != nil {
		return "", fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Step 3: Verify signature with Kitchen and get token
	token, err := c.verifyChallenge(nonce, signature)
	if err != nil {
		return "", err
	}

	return token, nil
}

// connectToSSHAgent connects to the SSH agent via SSH_AUTH_SOCK.
func connectToSSHAgent() (net.Conn, error) {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		return nil, ErrNoSSHAgent
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent at %s: %w", socketPath, err)
	}

	return conn, nil
}

// findKey finds the appropriate SSH key to use from the agent.
func (c *SSHAuthClient) findKey(keys []*agent.Key) (ssh.PublicKey, error) {
	// If keyComment is specified, filter by it
	if c.keyComment != "" {
		for _, k := range keys {
			if k.Comment == c.keyComment {
				return k, nil
			}
		}
		return nil, fmt.Errorf("%w: no key with comment %q", ErrKeyNotFound, c.keyComment)
	}

	// Otherwise, use the first key (most recently added)
	return keys[0], nil
}

// ChallengeRequest matches Kitchen's expected format.
type challengeRequest struct {
	Operator    string `json:"operator"`
	Fingerprint string `json:"pubkey_fp"`
}

// ChallengeResponse from Kitchen.
type challengeResponse struct {
	Nonce string `json:"nonce"`
}

// requestChallenge requests a challenge nonce from Kitchen.
func (c *SSHAuthClient) requestChallenge(fingerprint string) ([]byte, error) {
	reqBody, err := json.Marshal(challengeRequest{
		Operator:    c.operator,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.kitchenURL+"/auth/challenge",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to request challenge: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s (status %d)", ErrAuthFailed, string(body), resp.StatusCode)
	}

	var cr challengeResponse
	if jsonErr := json.Unmarshal(body, &cr); jsonErr != nil {
		return nil, fmt.Errorf("failed to decode challenge response: %w", jsonErr)
	}

	nonce, err := base64.StdEncoding.DecodeString(cr.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	return nonce, nil
}

// VerifyRequest matches Kitchen's expected format.
type verifyRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// VerifyResponse from Kitchen.
type verifyResponse struct {
	Token    string `json:"token"`
	Operator string `json:"operator"`
}

// verifyChallenge sends the signed challenge to Kitchen and gets a token.
func (c *SSHAuthClient) verifyChallenge(nonce []byte, sig *ssh.Signature) (string, error) {
	// Marshal signature to SSH wire format
	sigBytes := ssh.Marshal(sig)

	reqBody, err := json.Marshal(verifyRequest{
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Signature: base64.StdEncoding.EncodeToString(sigBytes),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal verify request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.kitchenURL+"/auth/verify",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return "", fmt.Errorf("failed to verify challenge: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %s (status %d)", ErrAuthFailed, string(body), resp.StatusCode)
	}

	var vr verifyResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return "", fmt.Errorf("failed to decode verify response: %w", err)
	}

	return vr.Token, nil
}

// ListAgentKeys returns the SSH keys available in the agent.
// Useful for debugging or letting users select which key to use.
func ListAgentKeys() ([]*agent.Key, error) {
	conn, err := connectToSSHAgent()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sshAgent := agent.NewClient(conn)
	return sshAgent.List()
}

// KeyInfo contains information about an SSH key.
type KeyInfo struct {
	Fingerprint   string
	Comment       string
	Type          string
	AuthorizedKey string // Full line for authorized_keys file
}

// GetKeyInfo returns information about SSH keys in the agent.
func GetKeyInfo() ([]KeyInfo, error) {
	keys, err := ListAgentKeys()
	if err != nil {
		return nil, err
	}

	info := make([]KeyInfo, len(keys))
	for i, k := range keys {
		// Marshal to authorized_keys format
		authKey := string(ssh.MarshalAuthorizedKey(k))
		// Trim trailing newline
		if authKey != "" && authKey[len(authKey)-1] == '\n' {
			authKey = authKey[:len(authKey)-1]
		}

		info[i] = KeyInfo{
			Fingerprint:   ssh.FingerprintSHA256(k),
			Comment:       k.Comment,
			Type:          k.Type(),
			AuthorizedKey: authKey,
		}
	}
	return info, nil
}
