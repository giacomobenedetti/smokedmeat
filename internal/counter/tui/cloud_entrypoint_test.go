// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudShellEntrypoint_GCPWritesProjectAndWarnings(t *testing.T) {
	shellHome := t.TempDir()
	stubDir := t.TempDir()

	pythonStub := filepath.Join(stubDir, "python3")
	require.NoError(t, os.WriteFile(pythonStub, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	gcpInit := filepath.Join(stubDir, "gcp-init.py")
	require.NoError(t, os.WriteFile(gcpInit, []byte("print('ok')\n"), 0o644))

	scriptPath := filepath.Join("..", "..", "..", "deployments", "cloud-shell-entrypoint.sh")
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"HOME="+shellHome,
		"SM_PROVIDER=gcp",
		"SM_METHOD=oidc",
		"SM_SHELL_HOME="+shellHome,
		"SM_ENTRYPOINT_WRITE_ONLY=1",
		"SM_GCP_INIT_SCRIPT="+gcpInit,
		"SM_GCP_ACCOUNT=sa@whooli.iam.gserviceaccount.com",
		"CLOUDSDK_AUTH_ACCESS_TOKEN=ya29.token",
		"CLOUDSDK_CORE_PROJECT=whooli",
		"CLOUDSDK_CONFIG="+filepath.Join(shellHome, "gcloud"),
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	properties, err := os.ReadFile(filepath.Join(shellHome, "gcloud", "properties"))
	require.NoError(t, err)
	assert.Contains(t, string(properties), "project = whooli")
	assert.Contains(t, string(properties), "account = sa@whooli.iam.gserviceaccount.com")

	boto, err := os.ReadFile(filepath.Join(shellHome, ".boto"))
	require.NoError(t, err)
	assert.Contains(t, string(boto), "default_project_id = whooli")

	bashrc, err := os.ReadFile(filepath.Join(shellHome, ".bashrc"))
	require.NoError(t, err)
	content := string(bashrc)
	assert.Contains(t, content, "gcloud: authenticated as sa@whooli.iam.gserviceaccount.com")
	assert.Contains(t, content, "WARNING: gcloud credential bootstrap failed")
	assert.Contains(t, content, "WARNING: gcloud project is unset")
	assert.Contains(t, content, "gcloud: project $project")
}

func TestCloudShellEntrypoint_GCPPreservesGoogleCloudProjectAlias(t *testing.T) {
	shellHome := t.TempDir()
	stubDir := t.TempDir()

	pythonStub := filepath.Join(stubDir, "python3")
	require.NoError(t, os.WriteFile(pythonStub, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	gcpInit := filepath.Join(stubDir, "gcp-init.py")
	require.NoError(t, os.WriteFile(gcpInit, []byte("print('ok')\n"), 0o644))

	scriptPath := filepath.Join("..", "..", "..", "deployments", "cloud-shell-entrypoint.sh")
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"HOME="+shellHome,
		"SM_PROVIDER=gcp",
		"SM_METHOD=oidc",
		"SM_SHELL_HOME="+shellHome,
		"SM_ENTRYPOINT_WRITE_ONLY=1",
		"SM_GCP_INIT_SCRIPT="+gcpInit,
		"GOOGLE_CLOUD_PROJECT=whooli-alias",
		"CLOUDSDK_CONFIG="+filepath.Join(shellHome, "gcloud"),
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	properties, err := os.ReadFile(filepath.Join(shellHome, "gcloud", "properties"))
	require.NoError(t, err)
	assert.Contains(t, string(properties), "project = whooli-alias")

	boto, err := os.ReadFile(filepath.Join(shellHome, ".boto"))
	require.NoError(t, err)
	assert.Contains(t, string(boto), "default_project_id = whooli-alias")
}

func TestCloudShellEntrypoint_BannerWidthsMatch(t *testing.T) {
	shellHome := t.TempDir()
	stubDir := t.TempDir()

	pythonStub := filepath.Join(stubDir, "python3")
	require.NoError(t, os.WriteFile(pythonStub, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	gcpInit := filepath.Join(stubDir, "gcp-init.py")
	require.NoError(t, os.WriteFile(gcpInit, []byte("print('ok')\n"), 0o644))

	scriptPath := filepath.Join("..", "..", "..", "deployments", "cloud-shell-entrypoint.sh")
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"HOME="+shellHome,
		"SM_PROVIDER=gcp",
		"SM_METHOD=oidc",
		"SM_SHELL_HOME="+shellHome,
		"SM_ENTRYPOINT_WRITE_ONLY=1",
		"SM_GCP_INIT_SCRIPT="+gcpInit,
		"SM_SHARED=/config/cloud-shell/shared/sm-cloud-3029658622",
		"CLOUDSDK_CONFIG="+filepath.Join(shellHome, "gcloud"),
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	bashrc, err := os.ReadFile(filepath.Join(shellHome, ".bashrc"))
	require.NoError(t, err)

	for _, line := range strings.Split(string(bashrc), "\n") {
		if !strings.HasPrefix(line, "echo '│") && !strings.HasPrefix(line, "echo '╭") && !strings.HasPrefix(line, "echo '╰") {
			continue
		}
		rendered := strings.TrimPrefix(line, "echo '")
		rendered = strings.TrimSuffix(rendered, "'")
		assert.Len(t, []rune(rendered), 51, "banner line width mismatch: %q", rendered)
	}
	assert.Contains(t, string(bashrc), "SmokedMeat Cloud Shell (gcp via oidc)")
	assert.Contains(t, string(bashrc), "Runtime:   ephemeral container")
	assert.Contains(t, string(bashrc), "Persist:   /shell is host mounted")
	assert.Contains(t, string(bashrc), "Transfer:  use /shared for copy in/out")
	assert.Contains(t, string(bashrc), "...shell/shared/sm-cloud-3029658622")
}

func TestCloudShellEntrypoint_SSHBannerOmitsSharedTransferHint(t *testing.T) {
	shellHome := t.TempDir()

	scriptPath := filepath.Join("..", "..", "..", "deployments", "cloud-shell-entrypoint.sh")
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"HOME="+shellHome,
		"SM_PROVIDER=ssh",
		"SM_METHOD=git",
		"SM_SHELL_HOME="+shellHome,
		"SM_ENTRYPOINT_WRITE_ONLY=1",
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	bashrc, err := os.ReadFile(filepath.Join(shellHome, ".bashrc"))
	require.NoError(t, err)

	content := string(bashrc)
	assert.Contains(t, content, "Runtime:   ephemeral container")
	assert.Contains(t, content, "Persist:   /shell is host mounted")
	assert.NotContains(t, content, "Transfer:  use /shared for copy in/out")
	assert.NotContains(t, content, "Shared:")
}
