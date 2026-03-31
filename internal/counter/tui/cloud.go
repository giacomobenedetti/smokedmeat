// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

type CloudState struct {
	Provider       string
	Method         string
	Credentials    map[string]string
	RawCredentials map[string]string
	PivotTime      time.Time
	ResourceCount  int
	Expiry         time.Time
	TempDir        string
}

var nativeCloudQueries = map[string]map[string]string{
	"aws": {
		"identity": "sts:GetCallerIdentity",
		"buckets":  "s3:ListBuckets",
		"ecr":      "ecr:DescribeRepositories",
	},
	"gcp": {
		"identity": "cloudresourcemanager:GetProject",
		"projects": "cloudresourcemanager:ListProjects",
	},
	"azure": {
		"identity":        "subscriptions:List",
		"storage":         "storage:ListAccounts",
		"resource-groups": "resources:ListResourceGroups",
		"acr":             "containerregistry:ListRegistries",
	},
}

func (m Model) executeCloudCommand(args []string) (tea.Model, tea.Cmd) {
	if m.cloudState == nil {
		m.AddOutput("error", "No active cloud session. Run 'pivot aws/gcp/azure' first.")
		return m, nil
	}

	if len(args) == 0 {
		m.showCloudStatus()
		return m, nil
	}

	subCmd := args[0]

	switch subCmd {
	case "status":
		m.showCloudStatus()
		return m, nil

	case "shell":
		return m.executeCloudShell()

	case "export":
		m.showCloudExport()
		return m, nil

	default:
		provider := m.cloudState.Provider
		nativeQueries, ok := nativeCloudQueries[provider]
		if !ok {
			m.AddOutput("error", fmt.Sprintf("No cloud queries are defined for provider: %s", provider))
			return m, nil
		}

		if _, isNative := nativeQueries[subCmd]; !isNative {
			m.AddOutput("error", fmt.Sprintf("Unknown cloud subcommand: %s", subCmd))
			m.showCloudShortcuts()
			return m, nil
		}

		if m.activeAgent == nil {
			m.AddOutput("error", "No active agent for cloud queries. Use 'cloud shell' for local exploration.")
			return m, nil
		}

		return m, m.sendOrder("cloud-query", []string{provider, subCmd})
	}
}

// ---------------------------------------------------------------------------
// Cloud session management
// ---------------------------------------------------------------------------

func (m *Model) cleanupCloudSession() {
	if m.cloudState == nil {
		return
	}
	if m.cloudState.TempDir != "" {
		os.RemoveAll(m.cloudState.TempDir)
		m.cloudState.TempDir = ""
	}
}

func smokedmeatDir() string {
	if dir := os.Getenv("SMOKEDMEAT_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".smokedmeat")
}

func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\"'\"'")
}

func sortedCredKeys(creds map[string]string) []string {
	skip := map[string]bool{
		"CREDENTIAL_CONFIG_JSON": true,
		"Expiration":             true,
		"EXPIRES_ON":             true,
	}
	tokenKeys := map[string]bool{
		"ACCESS_TOKEN":               true,
		"AWS_SESSION_TOKEN":          true,
		"AWS_SECRET_ACCESS_KEY":      true,
		"CLOUDSDK_AUTH_ACCESS_TOKEN": true,
	}

	var normal, tokens []string
	for k := range creds {
		if skip[k] {
			continue
		}
		if tokenKeys[k] {
			tokens = append(tokens, k)
		} else {
			normal = append(normal, k)
		}
	}
	sort.Strings(normal)
	sort.Strings(tokens)
	return append(normal, tokens...)
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

func (m *Model) showCloudStatus() {
	cs := m.cloudState
	m.activityLog.Add(IconInfo, fmt.Sprintf("Cloud Session: %s (via %s)", cs.Provider, cs.Method))
	m.activityLog.Add(IconInfo, fmt.Sprintf("  Connected: %s ago", time.Since(cs.PivotTime).Truncate(time.Second)))
	if !cs.Expiry.IsZero() {
		remaining := time.Until(cs.Expiry).Truncate(time.Second)
		if remaining > 0 {
			m.activityLog.Add(IconInfo, fmt.Sprintf("  Expires in: %s", remaining))
		} else {
			m.activityLog.Add(IconWarning, "  Credentials EXPIRED")
		}
	}
	m.activityLog.Add(IconInfo, fmt.Sprintf("  Resources: %d discovered", cs.ResourceCount))

	if len(cs.Credentials) > 0 {
		m.activityLog.Add(IconInfo, "  Credentials:")
		for k, v := range cs.Credentials {
			m.activityLog.Add(IconInfo, fmt.Sprintf("    %s = %s", k, v))
		}
	}

	m.activityLog.Add(IconInfo, "  cloud shell  → local cloud CLI shell")
	m.showCloudShortcuts()
}

func (m *Model) showCloudShortcuts() {
	if m.cloudState == nil {
		return
	}

	provider := m.cloudState.Provider
	nativeQueries, ok := nativeCloudQueries[provider]
	if !ok {
		return
	}

	names := make([]string, 0, len(nativeQueries))
	for name := range nativeQueries {
		names = append(names, name)
	}
	sort.Strings(names)

	m.activityLog.Add(IconInfo, fmt.Sprintf("  Quick checks (%s):", provider))
	for _, name := range names {
		m.activityLog.Add(IconInfo, fmt.Sprintf("    cloud %-16s → [api] %s", name, nativeQueries[name]))
	}
	m.activityLog.Add(IconInfo, "    cloud export         → show env vars for external tools")
}

func (m *Model) handleCloudQueryResult(qr *models.CloudQueryResult) {
	if !qr.Success {
		msg := fmt.Sprintf("cloud %s failed: %s", qr.QueryType, summarizeCloudQueryError(qr.Error))
		m.activityLog.Add(IconError, msg)
		m.AddOutput("error", msg)
		return
	}

	summary := fmt.Sprintf("Cloud query: %s/%s → %d resources", qr.Provider, qr.QueryType, len(qr.Resources))
	m.activityLog.Add(IconSuccess, summary)
	m.AddOutput("success", summary)
	for i, r := range qr.Resources {
		if i >= 25 {
			msg := fmt.Sprintf("  ... and %d more", len(qr.Resources)-25)
			m.activityLog.Add(IconInfo, msg)
			m.AddOutput("info", msg)
			break
		}
		label := r.Name
		if label == "" {
			label = r.ID
		}
		line := fmt.Sprintf("  [%s] %s", r.Type, label)
		m.activityLog.Add(IconInfo, line)
		m.AddOutput("info", line)
	}
}

func summarizeCloudQueryError(err string) string {
	summary := strings.Join(strings.Fields(err), " ")
	const maxLen = 220
	if len(summary) > maxLen {
		return summary[:maxLen-3] + "..."
	}
	return summary
}

func (m *Model) showCloudExport() {
	if m.cloudState == nil {
		m.activityLog.Add(IconWarning, "No cloud credentials to export")
		return
	}

	creds := m.cloudState.RawCredentials
	if len(creds) == 0 {
		creds = m.cloudState.Credentials
	}
	if len(creds) == 0 {
		m.activityLog.Add(IconWarning, "No cloud credentials to export")
		return
	}

	m.activityLog.Add(IconInfo, fmt.Sprintf("Export for %s:", m.cloudState.Provider))
	keys := sortedCredKeys(creds)
	for _, k := range keys {
		m.activityLog.Add(IconInfo, fmt.Sprintf("export %s='%s'", k, shellEscape(creds[k])))
	}
}
