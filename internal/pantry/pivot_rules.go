// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import "strings"

func ProjectPivots(asset Asset) []PivotProjection {
	switch asset.Type {
	case AssetSecret:
		return projectSecretPivots(asset)
	case AssetToken:
		return projectTokenPivots(asset)
	default:
		return nil
	}
}

func projectSecretPivots(asset Asset) []PivotProjection {
	name := strings.ToUpper(asset.Name)

	var projections []PivotProjection

	switch {
	case strings.Contains(name, "AWS"):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "aws_access_key",
			Provider:       "aws",
			Actions:        []string{"Check STS identity", "List S3 buckets", "Enumerate IAM"},
			Commands:       []string{"order exec aws sts get-caller-identity", "order exec aws s3 ls"},
		})
	case strings.Contains(name, "GCP") || strings.Contains(name, "GOOGLE"):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "gcp",
			Provider:       "gcp",
			Actions:        []string{"List GCS buckets", "List projects"},
			Commands:       []string{"order exec gcloud projects list"},
		})
	case strings.Contains(name, "AZURE"):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "azure",
			Provider:       "azure",
			Actions:        []string{"List resource groups", "List storage"},
			Commands:       []string{"order exec az group list"},
		})
	case strings.Contains(name, "NPM_TOKEN") || strings.Contains(name, "NPM_AUTH"):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "npm",
			Provider:       "npm",
			Actions:        []string{"Publish package (supply chain)"},
			Commands:       []string{"order exec npm whoami"},
		})
	case strings.Contains(name, "APP_KEY") || strings.Contains(name, "APP_PEM") ||
		strings.Contains(name, "APP_PRIVATE") || (strings.Contains(name, "GITHUB_APP") && strings.Contains(name, "KEY")):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "github_app_key",
			Provider:       "github",
			Actions:        []string{"Exchange PEM for installation token (ghs_*)"},
			Commands:       []string{"pivot app"},
		})
	case strings.Contains(name, "SSH") || strings.Contains(name, "PRIVATE_KEY") || strings.Contains(name, "DEPLOY_KEY"):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "ssh_key",
			Provider:       "ssh",
			Actions:        []string{"Test against github.com"},
			Commands:       []string{"order exec ssh -T git@github.com"},
		})
	case strings.Contains(name, "SIGNING"):
		projections = append(projections, PivotProjection{
			CredentialName: asset.Name,
			CredentialType: "signing_key",
			Provider:       "signing",
			Actions:        []string{"Sign commits/artifacts"},
		})
	}

	return projections
}

func projectTokenPivots(asset Asset) []PivotProjection {
	tokenType, _ := asset.Properties["token_type"].(string)
	scopes := asset.StringSliceProperty("scopes")

	var projections []PivotProjection

	switch tokenType {
	case "oidc":
		projections = append(projections, projectOIDCPivots(asset)...)
	case "github_token":
		projections = append(projections, projectGitHubTokenPivots(asset, scopes)...)
	}

	return projections
}

func projectOIDCPivots(asset Asset) []PivotProjection {
	provider, _ := asset.Properties["provider"].(string)
	switch strings.ToLower(provider) {
	case "aws":
		return []PivotProjection{{
			CredentialName: asset.Name,
			CredentialType: "oidc",
			Provider:       "aws",
			Actions:        []string{"STS AssumeRoleWithWebIdentity"},
			Commands:       []string{"order exec aws sts assume-role-with-web-identity"},
		}}
	case "gcp":
		return []PivotProjection{{
			CredentialName: asset.Name,
			CredentialType: "oidc",
			Provider:       "gcp",
			Actions:        []string{"Exchange for GCP access token"},
		}}
	case "azure":
		return []PivotProjection{{
			CredentialName: asset.Name,
			CredentialType: "oidc",
			Provider:       "azure",
			Actions:        []string{"Exchange for Azure AD token"},
		}}
	default:
		return []PivotProjection{{
			CredentialName: asset.Name,
			CredentialType: "oidc",
			Provider:       "cloud",
			Actions:        []string{"Exchange OIDC token for cloud credentials"},
		}}
	}
}

func projectGitHubTokenPivots(asset Asset, scopes []string) []PivotProjection {
	var actions []string
	var commands []string

	for _, scope := range scopes {
		s := strings.ToLower(scope)
		switch {
		case strings.Contains(s, "contents") && strings.Contains(s, "write"):
			action := "Pivot to workflows via contents:write"
			if scopeProp, _ := asset.Properties["scope"].(string); isOrgRepoString(scopeProp) {
				action = "Pivot to workflows in " + scopeProp + " (contents:write)"
			}
			actions = append(actions, action)
			commands = append(commands, "pivot github")
		case strings.Contains(s, "actions") && strings.Contains(s, "write"):
			actions = append(actions, "Dispatch workflows via actions:write")
			commands = append(commands, "pivot dispatch")
		}
	}

	if len(actions) == 0 {
		return nil
	}

	return []PivotProjection{{
		CredentialName: asset.Name,
		CredentialType: "github_token",
		Provider:       "github",
		Actions:        actions,
		Commands:       commands,
	}}
}

func isOrgRepoString(s string) bool {
	parts := strings.SplitN(s, "/", 3)
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}
