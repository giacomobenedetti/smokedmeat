// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	infraRepo            = "whooli/infrastructure-definitions"
	benchmarkBotWorkflow = ".github/workflows/benchmark-bot.yml"
	deployWorkflow       = ".github/workflows/deploy.yml"
	flagBucket           = "whooli-newcleus-benchmarks"
)

var (
	flagRe = regexp.MustCompile(`(?i)(SM\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\})`)
)

type vaultToken struct {
	Name        string `yaml:"name"`
	Value       string `yaml:"value"`
	Type        string `yaml:"type,omitempty"`
	PairedAppID string `yaml:"paired_app_id,omitempty"`
	Repository  string `yaml:"repository,omitempty"`
	Workflow    string `yaml:"workflow,omitempty"`
	Job         string `yaml:"job,omitempty"`
}

type vaultFile struct {
	Tokens []vaultToken `yaml:"tokens"`
}

type appInstallationsResponse struct {
	Installations []struct {
		ID      int64  `json:"id"`
		Account string `json:"account"`
		AppSlug string `json:"app_slug"`
	} `json:"installations"`
}

type appTokenResponse struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

type workflowRunsResponse struct {
	WorkflowRuns []workflowRun `json:"workflow_runs"`
}

type workflowRun struct {
	ID         int64     `json:"id"`
	HTMLURL    string    `json:"html_url"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	HeadBranch string    `json:"head_branch"`
	Event      string    `json:"event"`
	CreatedAt  time.Time `json:"created_at"`
	RunAttempt int       `json:"run_attempt"`
}

type workflowFileResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type actionsCachesResponse struct {
	TotalCount    int            `json:"total_count"`
	ActionsCaches []actionsCache `json:"actions_caches"`
}

type actionsCache struct {
	ID        int64     `json:"id"`
	Ref       string    `json:"ref"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

func TestGOATFlagPath(t *testing.T) {
	token := getEnvOrFile("GITHUB_TOKEN", e2eEnvPath)
	require.NotEmpty(t, token, "GITHUB_TOKEN required (set in .claude/e2e/.env)")

	kitchenURL := getEnvOrFile("KITCHEN_URL", e2eEnvPath)
	require.NotEmpty(t, kitchenURL, "KITCHEN_URL required")
	authToken := getEnvOrFile("AUTH_TOKEN", e2eEnvPath)
	require.NotEmpty(t, authToken, "AUTH_TOKEN required")
	kitchenExternalURL := getEnvOrFile("KITCHEN_EXTERNAL_URL", e2eEnvPath)
	require.NotEmpty(t, kitchenExternalURL, "KITCHEN_EXTERNAL_URL required")

	root := findProjectRoot()
	require.NotEmpty(t, root, "could not find project root")

	sessionID := "e2e-goat"

	require.NoError(t, resetE2EWorkspace())
	require.NoError(t, waitForKitchenHealth(root, 90*time.Second))
	require.NoError(t, writeConfig(token, targetRepo))
	require.NoError(t, restartCounter(sessionID))

	tmux := newTmuxController(tmuxSessionName)

	waitForReconPhase(t, tmux)
	requireContent(t, tmux, "whooli", 15*time.Second, "Attack tree should show target org")
	requireContent(t, tmux, "xyz", 15*time.Second, "Attack tree should show target repo")

	vulnKey := "2"
	if capture := tmux.CaptureClean(); capture != "" {
		if key := findMenuVulnAll(capture, "issue body", "auto-labeler"); key != "" {
			vulnKey = key
		}
	}

	openDeployWizardFromMenu(t, tmux, vulnKey)
	completeIssueDeployWizard(t, tmux, 4)
	requireContent(t, tmux, "5m0s", 2*time.Second, "Dwell time should be 5m0s")
	require.NoError(t, tmux.SendKeys("Enter"))

	deployPhase := waitForAny(tmux, []string{"Phase:Waiting", "Phase:Post-Exploit"}, 30*time.Second)
	require.NotEmpty(t, deployPhase, "Phase should transition after deploy")

	issue := findDeployedIssue(t, 30*time.Second)
	require.NotNil(t, issue, "Should find deployed issue on "+targetRepo)
	t.Logf("Found issue #%d: %s", issue.Number, issue.URL)
	t.Cleanup(func() { closeIssueByNumber(t, issue.Number) })

	if deployPhase == "Phase:Waiting" {
		require.True(t, waitForContent(tmux, "Phase:Post-Exploit", 5*time.Minute),
			"Brisket should connect and transition to Post-Exploit")
	}

	requireContent(t, tmux, "Agent:", 10*time.Second, "Should have active agent")
	closeIssueByNumber(t, issue.Number)

	ensureShortcutFocus(t, tmux)
	require.NoError(t, tmux.SendKeys("r"))
	requireContent(t, tmux, "Phase:Recon", 10*time.Second, "Should return to Recon phase")

	runCounterCommand(t, tmux, "exploit comment")
	requireContent(t, tmux, "Step 1/3", 10*time.Second, "Comment foothold wizard should appear")
	completeIssueDeployWizard(t, tmux, 4)
	requireContent(t, tmux, "5m0s", 2*time.Second, "Comment foothold dwell time should be 5m0s")
	require.NoError(t, tmux.SendKeys("Enter"))

	deployPhase = waitForAny(tmux, []string{"Phase:Waiting", "Phase:Post-Exploit"}, 30*time.Second)
	require.NotEmpty(t, deployPhase, "Comment foothold should transition after deploy")

	appIssue := findDeployedIssue(t, 30*time.Second, issue.Number)
	require.NotNil(t, appIssue, "Should find second deployed issue on "+targetRepo)
	t.Logf("Found app issue #%d: %s", appIssue.Number, appIssue.URL)
	t.Cleanup(func() { closeIssueByNumber(t, appIssue.Number) })

	if deployPhase == "Phase:Waiting" {
		require.True(t, waitForContent(tmux, "Phase:Post-Exploit", 5*time.Minute),
			"Second foothold should transition to Post-Exploit")
	}

	secondFootholdMarker := waitForAny(tmux, []string{
		".github/workflows/whooli-analyzer.yml",
		"GitHub App (WHOOLI_BOT_APP_PRIVATE_KEY)",
		"WHOOLI_BOT_APP_PRIVATE_KEY",
	}, 30*time.Second)
	require.NotEmpty(t, secondFootholdMarker, "Second foothold should land on whooli-analyzer")
	ensureLootFocus(t, tmux)
	requireContent(t, tmux, "GitHub App (WHOOLI_BOT_APP_PRIVATE_KEY)", 2*time.Minute, "Collected App key should land in the loot stash before export")
	require.NoError(t, tmux.SendKeys("e"))
	requireContent(t, tmux, "Exported", 10*time.Second, "App-key export should succeed")
	appKey := requireVaultAppKey(t, root)
	appToken := mintInstallationToken(t, kitchenURL, authToken, appKey)

	runCounterCommand(t, tmux, "set token "+appToken)
	requireContent(t, tmux, maskTokenValue(appToken), 10*time.Second, "App installation token should become the active token")

	runCounterCommand(t, tmux, "set target repo:"+infraRepo)
	runCounterCommand(t, tmux, "status")
	requireContent(t, tmux, "Target: repo:"+infraRepo, 10*time.Second, "Target should switch to infrastructure repo")

	analyzeCurrentTarget(t, tmux)
	requireContent(t, tmux, benchmarkBotWorkflow, 30*time.Second, "Infrastructure analysis should surface the issue-comment writer workflow")
	purgeRepoCachesByPrefix(t, appToken, infraRepo, "setup-go-", "refs/heads/main")

	ensureShortcutFocus(t, tmux)
	require.NoError(t, tmux.SendKeys("r"))
	requireContent(t, tmux, "Phase:Recon", 10*time.Second, "Should return to Recon phase for private repo exploitation")

	runCounterCommand(t, tmux, "set token "+appToken)
	requireContent(t, tmux, maskTokenValue(appToken), 10*time.Second, "App installation token should remain active in Recon")

	writerVulnQuery := requireCacheWriterVulnQuery(t, kitchenURL, authToken, infraRepo, benchmarkBotWorkflow)
	runCounterCommand(t, tmux, "exploit "+writerVulnQuery)
	requireContent(t, tmux, "Step 1/3", 10*time.Second, "Infrastructure writer wizard should appear")
	completeCommentDeployWizardWithCachePoison(t, tmux, 0, 4, deployWorkflow, "")
	requireContent(t, tmux, benchmarkBotWorkflow, 5*time.Second, "Writer workflow should be the benchmark bot workflow")
	requireContent(t, tmux, deployWorkflow, 5*time.Second, "Deploy workflow should be selectable as the cache poison victim")
	require.NoError(t, tmux.SendKeys("Enter"))

	requireContent(t, tmux, "Phase:Waiting", 30*time.Second, "Cache poison deployment should enter waiting phase")
	requireContent(t, tmux, "Writer cache: armed", 2*time.Minute, "Cache poison flow should arm the writer cache before the victim workflow runs")
	requireContent(t, tmux, "Victim callback: waiting", 5*time.Second, "Victim callback should still be pending before the victim workflow runs")
	armNextImplantWithDwell(t, tmux, deployWorkflow)
	triggerMethod, triggeredRun := triggerVictimDeploy(t, appToken, infraRepo, deployWorkflow)
	t.Logf("Triggered victim deploy via %s: %s", triggerMethod, triggeredRun.HTMLURL)

	requireContent(t, tmux, "Phase:Post-Exploit", 8*time.Minute, "Victim callback should enter post-exploit mode after dwell is armed")
	runCounterCommand(t, tmux, "status")
	requireContent(t, tmux, "Agent:", 10*time.Second, "Status should show an active agent")

	runCounterCommand(t, tmux, "pivot gcp")
	cloudPivot := waitForAny(tmux, []string{
		"Cloud pivot to gcp succeeded",
		"OIDC pivot to gcp successful",
		"Cloud pivot: gcp via oidc",
		"pivot to gcp failed",
		"Cloud pivot to gcp failed",
	}, 90*time.Second)
	require.NotEmpty(t, cloudPivot, "Cloud pivot should produce output")
	require.NotEqual(t, "pivot to gcp failed", cloudPivot, "GCP pivot should succeed")
	require.NotEqual(t, "Cloud pivot to gcp failed", cloudPivot, "GCP pivot should succeed")

	verifyPantryHasCloudResources(t, kitchenURL, authToken)

	runCounterCommand(t, tmux, "cloud shell")
	cloudShellReady := waitForAny(tmux, []string{
		"SmokedMeat Cloud Shell",
		"[sm:gcp/",
	}, 30*time.Second)
	require.NotEmpty(t, cloudShellReady, "cloud shell banner or prompt must appear")

	require.NoError(t, tmux.TypeText("gsutil ls gs://"+flagBucket+"/"))
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "flag.txt", 30*time.Second, "Bucket listing should show flag.txt")

	require.NoError(t, tmux.TypeText("gsutil cat gs://"+flagBucket+"/flag.txt"))
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	require.True(t, waitForFlag(tmux, 30*time.Second), "flag content should appear in cloud shell output")

	flagContent := extractFlagContent(tmux.CaptureClean())
	require.NotEmpty(t, flagContent, "flag content should be extractable from cloud shell output")
	t.Logf("FLAG CAPTURED: %s", flagContent)

	require.NoError(t, tmux.TypeText("exit"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	waitForAny(tmux, []string{"❯", "Phase:Post-Exploit", "SmokedMeat Counter"}, 20*time.Second)
}

func requireVaultAppKey(t *testing.T, root string) vaultToken {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(root, e2eVault))
	require.NoError(t, err)

	var vault vaultFile
	require.NoError(t, yaml.Unmarshal(data, &vault))

	for _, token := range vault.Tokens {
		if token.Name == "WHOOLI_BOT_APP_PRIVATE_KEY" && token.Value != "" && token.PairedAppID != "" {
			return token
		}
	}

	t.Fatalf("vault did not contain a paired WHOOLI_BOT_APP_PRIVATE_KEY")
	return vaultToken{}
}

func mintInstallationToken(t *testing.T, kitchenURL, authToken string, key vaultToken) string {
	t.Helper()

	var installs appInstallationsResponse
	kitchenRequest(t, kitchenURL, authToken, http.MethodPost, "/github/app/installations", map[string]string{
		"pem":    key.Value,
		"app_id": key.PairedAppID,
	}, &installs, http.StatusOK)
	require.NotEmpty(t, installs.Installations, "app installations should not be empty")

	installationID := installs.Installations[0].ID
	for _, installation := range installs.Installations {
		if installation.Account == targetOrg {
			installationID = installation.ID
			break
		}
	}

	var tokenResp appTokenResponse
	kitchenRequest(t, kitchenURL, authToken, http.MethodPost, "/github/app/token", map[string]any{
		"pem":             key.Value,
		"app_id":          key.PairedAppID,
		"installation_id": installationID,
	}, &tokenResp, http.StatusOK)
	require.NotEmpty(t, tokenResp.Token, "installation token should not be empty")
	t.Logf("App token permissions: %+v", tokenResp.Permissions)
	return tokenResp.Token
}

func maskTokenValue(token string) string {
	if len(token) < 8 {
		return "***"
	}
	return token[:4] + "…" + token[len(token)-4:]
}

func requireCacheWriterVulnQuery(t *testing.T, kitchenURL, authToken, repo, workflow string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, kitchenURL+"/pantry", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := newInsecureHTTPClient(30 * time.Second).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Pantry request should succeed")

	var p pantry.Pantry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&p))

	for _, vuln := range p.FindVulnerabilities() {
		_, org, repoName := pantry.ParsePurl(vuln.Purl)
		if org == "" || repoName == "" {
			continue
		}
		vulnRepo := org + "/" + repoName
		path, _ := vuln.Properties["path"].(string)
		job, _ := vuln.Properties["job"].(string)
		writer, _ := vuln.Properties["cache_poison_writer"].(bool)
		if vulnRepo == repo && path == workflow && writer {
			return strings.TrimSpace(strings.Join([]string{vulnRepo, path, job}, " "))
		}
	}

	t.Fatalf("cache writer vulnerability not found for %s %s", repo, workflow)
	return ""
}

func listWorkflowRuns(t *testing.T, token, repo, workflowFile string) []workflowRun {
	t.Helper()

	workflowID := lookupWorkflowID(t, token, repo, workflowFile)

	var resp workflowRunsResponse
	githubRequest(t, token, http.MethodGet, fmt.Sprintf(
		"https://api.github.com/repos/%s/actions/workflows/%d/runs?per_page=20",
		repo,
		workflowID,
	), nil, &resp, http.StatusOK)
	return resp.WorkflowRuns
}

func workflowRunIndex(runs []workflowRun) map[int64]struct{} {
	seen := make(map[int64]struct{}, len(runs))
	for _, run := range runs {
		seen[run.ID] = struct{}{}
	}
	return seen
}

func purgeRepoCachesByPrefix(t *testing.T, token, repo, prefix, ref string) {
	t.Helper()

	var resp actionsCachesResponse
	githubRequest(t, token, http.MethodGet, fmt.Sprintf(
		"https://api.github.com/repos/%s/actions/caches?per_page=100",
		repo,
	), nil, &resp, http.StatusOK)

	matches := matchingActionsCaches(resp.ActionsCaches, prefix, ref)
	removed := 0
	for _, cache := range matches {
		githubRequest(t, token, http.MethodDelete, fmt.Sprintf(
			"https://api.github.com/repos/%s/actions/caches/%d",
			repo,
			cache.ID,
		), nil, nil, http.StatusNoContent, http.StatusOK)
		removed++
		t.Logf("Purged cache %d (%s created %s)", cache.ID, cache.Key, cache.CreatedAt.UTC().Format(time.RFC3339))
	}
	if removed == 0 {
		t.Logf("No matching caches to purge for %s prefix %q ref %q", repo, prefix, ref)
	}
}

func matchingActionsCaches(caches []actionsCache, prefix, ref string) []actionsCache {
	matches := make([]actionsCache, 0, len(caches))
	for _, cache := range caches {
		if prefix != "" && !strings.HasPrefix(cache.Key, prefix) {
			continue
		}
		if ref != "" && cache.Ref != ref {
			continue
		}
		matches = append(matches, cache)
	}
	return matches
}

func getWorkflowRun(t *testing.T, token, repo string, runID int64) workflowRun {
	t.Helper()

	var run workflowRun
	githubRequest(t, token, http.MethodGet, fmt.Sprintf(
		"https://api.github.com/repos/%s/actions/runs/%d",
		repo,
		runID,
	), nil, &run, http.StatusOK)
	require.NotZero(t, run.ID, "workflow run lookup should return a run")
	return run
}

func lookupWorkflowID(t *testing.T, token, repo, workflowFile string) int64 {
	t.Helper()

	var resp struct {
		Workflows []struct {
			ID   int64  `json:"id"`
			Path string `json:"path"`
		} `json:"workflows"`
	}
	githubRequest(t, token, http.MethodGet, fmt.Sprintf(
		"https://api.github.com/repos/%s/actions/workflows?per_page=100",
		repo,
	), nil, &resp, http.StatusOK)

	for _, workflow := range resp.Workflows {
		if workflow.Path == workflowFile {
			return workflow.ID
		}
	}

	t.Fatalf("workflow %s not found in %s", workflowFile, repo)
	return 0
}

func triggerVictimDeploy(t *testing.T, token, repo, workflowFile string) (string, workflowRun) {
	t.Helper()

	require.True(t, workflowSupportsDispatch(t, token, repo, workflowFile),
		"%s should support workflow_dispatch for the preferred GOAT path", workflowFile)

	seenRunIDs := workflowRunIndex(listWorkflowRuns(t, token, repo, workflowFile))

	githubRequest(t, token, http.MethodPost, fmt.Sprintf(
		"https://api.github.com/repos/%s/actions/workflows/%s/dispatches",
		repo,
		url.PathEscape(workflowFile),
	), map[string]string{"ref": "main"}, nil, http.StatusNoContent, http.StatusCreated, http.StatusAccepted)

	return "workflow_dispatch", waitForTriggeredWorkflowRun(t, token, repo, workflowFile, seenRunIDs, 60*time.Second)
}

func waitForNewWorkflowRun(t *testing.T, token, repo, workflowFile string, seenRunIDs map[int64]struct{}, event string, timeout time.Duration) workflowRun {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		runs := listWorkflowRuns(t, token, repo, workflowFile)
		for _, run := range runs {
			if _, seen := seenRunIDs[run.ID]; seen {
				continue
			}
			if event == "" || run.Event == event {
				return run
			}
		}
		time.Sleep(2 * time.Second)
	}

	t.Fatalf("new %q run for %s in %s did not appear within %s", event, workflowFile, repo, timeout)
	return workflowRun{}
}

func waitForTriggeredWorkflowRun(t *testing.T, token, repo, workflowFile string, seenRunIDs map[int64]struct{}, timeout time.Duration) workflowRun {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var newestRun workflowRun
	for time.Now().Before(deadline) {
		runs := listWorkflowRuns(t, token, repo, workflowFile)
		for _, run := range runs {
			if _, seen := seenRunIDs[run.ID]; seen {
				continue
			}
			if run.Event == "" {
				t.Logf("workflow run %d for %s in %s returned empty event", run.ID, workflowFile, repo)
				return run
			}
			if run.Event == "workflow_dispatch" {
				return run
			}
			if newestRun.ID == 0 {
				newestRun = run
			}
		}
		time.Sleep(2 * time.Second)
	}

	if newestRun.ID != 0 {
		t.Fatalf("workflow_dispatch did not produce a new dispatch run for %s in %s (newest run %d event=%s)",
			workflowFile, repo, newestRun.ID, newestRun.Event)
	}
	t.Fatalf("workflow_dispatch did not produce a new run for %s in %s within %s", workflowFile, repo, timeout)
	return workflowRun{}
}

func waitForWorkflowRunCompletion(t *testing.T, token, repo string, runID int64, timeout time.Duration) workflowRun {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		run := getWorkflowRun(t, token, repo, runID)
		if run.Status == "completed" {
			require.Equal(t, "success", run.Conclusion, "workflow run %d should succeed", runID)
			return run
		}
		time.Sleep(2 * time.Second)
	}

	t.Fatalf("workflow run %d in %s did not complete within %s", runID, repo, timeout)
	return workflowRun{}
}

func workflowSupportsDispatch(t *testing.T, token, repo, workflowFile string) bool {
	t.Helper()

	var wf workflowFileResponse
	githubRequest(t, token, http.MethodGet, fmt.Sprintf(
		"https://api.github.com/repos/%s/contents/%s?ref=main",
		repo,
		url.PathEscape(workflowFile),
	), nil, &wf, http.StatusOK)

	if wf.Encoding != "base64" || wf.Content == "" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(wf.Content, "\n", ""))
	require.NoError(t, err)
	return strings.Contains(string(decoded), "workflow_dispatch")
}

func kitchenRequest(t *testing.T, kitchenURL, authToken, method, path string, body any, out any, wantStatuses ...int) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, strings.TrimRight(kitchenURL, "/")+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := newInsecureHTTPClient(30 * time.Second).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	statusOK := false
	for _, want := range wantStatuses {
		if resp.StatusCode == want {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Fatalf("%s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		require.NoError(t, json.Unmarshal(respBody, out))
	}
}

func githubRequest(t *testing.T, token, method, requestURL string, body any, out any, wantStatuses ...int) {
	t.Helper()

	status, respBody, err := githubRequestRaw(token, method, requestURL, body)
	require.NoError(t, err)

	statusOK := false
	for _, want := range wantStatuses {
		if status == want {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Fatalf("%s %s returned %d: %s", method, requestURL, status, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		require.NoError(t, json.Unmarshal(respBody, out))
	}
}

func githubRequestRaw(token, method, requestURL string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, requestURL, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

func waitForFlag(tc *TmuxController, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if flagRe.MatchString(tc.CaptureClean()) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func extractFlagContent(capture string) string {
	return flagRe.FindString(capture)
}

func verifyPantryHasCloudResources(t *testing.T, kitchenURL, authToken string) {
	t.Helper()

	var graphData struct {
		Nodes []struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Label string `json:"label"`
			State string `json:"state"`
		} `json:"nodes"`
	}

	kitchenRequest(t, kitchenURL, authToken, http.MethodGet, "/graph/data", nil, &graphData, http.StatusOK)

	var cloudNodes []string
	for _, node := range graphData.Nodes {
		nodeType := strings.ToLower(node.Type)
		label := strings.ToLower(node.Label)
		if nodeType == "cloud" || nodeType == "token" ||
			strings.Contains(label, "oidc") || strings.Contains(label, "gcs_bucket") ||
			strings.Contains(label, "gcp") || strings.Contains(label, "deployer") {
			cloudNodes = append(cloudNodes, fmt.Sprintf("%s [%s] (%s)", node.Label, node.Type, node.State))
		}
	}

	assert.NotEmpty(t, cloudNodes, "Pantry graph should contain cloud-related nodes after the GCP pivot")
}
