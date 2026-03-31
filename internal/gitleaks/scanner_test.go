// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gitleaks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanDirectory_FindsPrivateKey(t *testing.T) {
	dir := t.TempDir()

	pemKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNFH1h5V1FBYY0rs5JmCnHOXYRklBzOVFnH0Kqd0Fv2Ay/bMen0IN9M3MmTJPl0J
BFG5sJn0Y8X/l2yJQyU8aRQ8gTn+g4R8bwpfn2pCQhyU8N+QV4+pkWHIdDd9hRFBD
OGKKSE3LhBvRQMzF0WCDKLQKA5pnC3PIWA2GewIDAQABAKCAQBa6YBFCo3vb5tyx
-----END RSA PRIVATE KEY-----`

	err := os.WriteFile(filepath.Join(dir, "test.md"), []byte("# Test\n\n```\n"+pemKey+"\n```\n"), 0644)
	require.NoError(t, err)

	result, err := ScanDirectory(context.Background(), dir)
	require.NoError(t, err)

	assert.NotEmpty(t, result.Findings, "should detect private key in markdown file")
	if len(result.Findings) > 0 {
		assert.Equal(t, "private-key", result.Findings[0].RuleID)
		assert.Contains(t, result.Findings[0].Secret, "BEGIN RSA PRIVATE KEY")
		assert.Contains(t, result.Findings[0].Secret, "END RSA PRIVATE KEY")
		assert.NotContains(t, result.Findings[0].Secret, "...")
	}
}

func TestScanDirectory_FindsPrivateKeyPlainFile(t *testing.T) {
	dir := t.TempDir()

	pemKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNFH1h5V1FBYY0rs5JmCnHOXYRklBzOVFnH0Kqd0Fv2Ay/bMen0IN9M3MmTJPl0J
BFG5sJn0Y8X/l2yJQyU8aRQ8gTn+g4R8bwpfn2pCQhyU8N+QV4+pkWHIdDd9hRFBD
OGKKSE3LhBvRQMzF0WCDKLQKA5pnC3PIWA2GewIDAQABAKCAQBa6YBFCo3vb5tyx
-----END RSA PRIVATE KEY-----`

	err := os.WriteFile(filepath.Join(dir, "id_rsa"), []byte(pemKey), 0600)
	require.NoError(t, err)

	result, err := ScanDirectory(context.Background(), dir)
	require.NoError(t, err)

	assert.NotEmpty(t, result.Findings, "should detect private key in plain file")
}

func TestScanDirectory_NoFindings(t *testing.T) {
	dir := t.TempDir()

	err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Hello\nNo secrets here\n"), 0644)
	require.NoError(t, err)

	result, err := ScanDirectory(context.Background(), dir)
	require.NoError(t, err)

	assert.Empty(t, result.Findings)
}
