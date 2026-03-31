// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransfer_NoArgs(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer(nil)

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "usage:")
}

func TestTransfer_UnknownOperation(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"invalid"})

	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Operation)
	assert.Contains(t, result.Error, "unknown operation")
}

func TestTransfer_DownloadMissingPath(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"download"})

	assert.False(t, result.Success)
	assert.Equal(t, "download", result.Operation)
	assert.Contains(t, result.Error, "usage:")
}

func TestTransfer_DownloadNonexistent(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"download", "/nonexistent/path/file.txt"})

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "file not found")
}

func TestTransfer_DownloadDirectory(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"download", "/tmp"})

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "cannot download directory")
}

func TestTransfer_DownloadFile(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := "Hello, World!"
	require.NoError(t, os.WriteFile(tmpFile, []byte(content), 0644))

	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"download", tmpFile})

	assert.True(t, result.Success)
	assert.Equal(t, "download", result.Operation)
	assert.Equal(t, tmpFile, result.Path)
	assert.Equal(t, int64(len(content)), result.Size)
	assert.NotEmpty(t, result.Data) // Base64 encoded data
	assert.Empty(t, result.Error)
}

func TestTransfer_UploadMissingArgs(t *testing.T) {
	agent := New(DefaultConfig())

	// Missing all args
	result := agent.Transfer([]string{"upload"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "usage:")

	// Missing data
	result = agent.Transfer([]string{"upload", "/tmp/test.txt"})
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "usage:")
}

func TestTransfer_UploadInvalidBase64(t *testing.T) {
	agent := New(DefaultConfig())
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	result := agent.Transfer([]string{"upload", tmpFile, "not-valid-base64!!!"})

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "failed to decode base64")
}

func TestTransfer_UploadAndDownloadRoundtrip(t *testing.T) {
	agent := New(DefaultConfig())
	tmpDir := t.TempDir()
	content := "Hello from roundtrip test!"

	// First, create a file and download it
	srcFile := filepath.Join(tmpDir, "source.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte(content), 0644))

	downloadResult := agent.Transfer([]string{"download", srcFile})
	require.True(t, downloadResult.Success)

	// Now upload to a new file
	dstFile := filepath.Join(tmpDir, "destination.txt")
	uploadResult := agent.Transfer([]string{"upload", dstFile, downloadResult.Data})

	assert.True(t, uploadResult.Success)
	assert.Equal(t, dstFile, uploadResult.Path)
	assert.Equal(t, int64(len(content)), uploadResult.Size)

	// Verify content matches
	readContent, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, content, string(readContent))
}

func TestTransfer_UploadCreatesDirectories(t *testing.T) {
	agent := New(DefaultConfig())
	tmpDir := t.TempDir()
	content := "Test content"

	// Download to get encoded content
	srcFile := filepath.Join(tmpDir, "source.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte(content), 0644))

	downloadResult := agent.Transfer([]string{"download", srcFile})
	require.True(t, downloadResult.Success)

	// Upload to nested directory that doesn't exist
	dstFile := filepath.Join(tmpDir, "nested", "subdir", "destination.txt")
	uploadResult := agent.Transfer([]string{"upload", dstFile, downloadResult.Data})

	assert.True(t, uploadResult.Success)

	// Verify file exists
	_, err := os.Stat(dstFile)
	assert.NoError(t, err)
}

func TestTransfer_ListMissingPath(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"list", "/nonexistent/path"})

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "path not found")
}

func TestTransfer_ListDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some test files
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755))

	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"list", tmpDir})

	assert.True(t, result.Success)
	assert.Equal(t, "list", result.Operation)
	assert.Equal(t, tmpDir, result.Path)
	assert.Len(t, result.Files, 3)

	// Verify file info
	fileNames := make(map[string]bool)
	for _, f := range result.Files {
		fileNames[f.Name] = true
	}
	assert.True(t, fileNames["file1.txt"])
	assert.True(t, fileNames["file2.txt"])
	assert.True(t, fileNames["subdir"])
}

func TestTransfer_ListFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("content"), 0644))

	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"list", tmpFile})

	assert.True(t, result.Success)
	assert.Len(t, result.Files, 1)
	assert.Equal(t, "test.txt", result.Files[0].Name)
	assert.Equal(t, int64(7), result.Files[0].Size) // "content" = 7 chars
	assert.False(t, result.Files[0].IsDir)
}

func TestTransfer_ListDefaultPath(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"list"})

	// Lists current directory
	assert.True(t, result.Success)
	assert.Equal(t, ".", result.Path)
	assert.NotEmpty(t, result.Files)
}

func TestTransfer_Duration(t *testing.T) {
	agent := New(DefaultConfig())
	result := agent.Transfer([]string{"list"})

	assert.GreaterOrEqual(t, result.Duration, float64(0))
}

func TestCompressDecompress_Roundtrip(t *testing.T) {
	original := []byte("Hello, this is test data that should be compressed and decompressed correctly!")

	compressed, err := compressData(original)
	require.NoError(t, err)
	assert.NotEmpty(t, compressed)

	decompressed, err := decompressData(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestCompressDecompress_Empty(t *testing.T) {
	original := []byte{}

	compressed, err := compressData(original)
	require.NoError(t, err)

	decompressed, err := decompressData(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestTransferResult_Marshal(t *testing.T) {
	result := &TransferResult{
		Success:   true,
		Operation: "download",
		Path:      "/test/path",
		Size:      1024,
	}

	data, err := result.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(data), `"success":true`)
	assert.Contains(t, string(data), `"operation":"download"`)
	assert.Contains(t, string(data), `"path":"/test/path"`)
	assert.Contains(t, string(data), `"size":1024`)
}
