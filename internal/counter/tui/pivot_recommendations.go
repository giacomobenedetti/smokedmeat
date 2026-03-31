// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"
)

type PivotRecommendation struct {
	Label       string
	Description string
	Command     string
	Priority    int
}

func credentialRecommendations(secret CollectedSecret, knownRepoCount int) []PivotRecommendation {
	var recs []PivotRecommendation

	if secret.CanUseAsSSHKey() {
		label := "Confirm GitHub SSH write access"
		if secret.Repository != "" {
			label = "Confirm GitHub SSH write access in " + repoOwner(secret.Repository)
		}
		recs = append(recs, PivotRecommendation{
			Label:       label,
			Description: "Probe read/write access on already discovered repos",
			Command:     "pivot ssh",
			Priority:    1,
		})
		return recs
	}

	switch secret.Type {
	case "github_pat", "github_fine_grained_pat":
		recs = append(recs, PivotRecommendation{
			Label:       fmt.Sprintf("Enumerate %d accessible repos", max(knownRepoCount, 1)),
			Description: "PAT has repo scope",
			Command:     "pivot github",
			Priority:    1,
		}, PivotRecommendation{
			Label:       "Analyze discovered repos",
			Description: "Scan new targets for vulns",
			Command:     "analyze pivots",
			Priority:    2,
		})

	case "github_token":
		label := "Pivot to workflows"
		if secret.BoundToRepo != "" {
			label = "Pivot to workflows in " + secret.BoundToRepo
		}
		recs = append(recs, PivotRecommendation{
			Label:       label,
			Description: "GITHUB_TOKEN can push code",
			Command:     "pivot github",
			Priority:    1,
		})
		for _, scope := range secret.Scopes {
			s := strings.ToLower(scope)
			if strings.Contains(s, "actions") && strings.Contains(s, "write") {
				recs = append(recs, PivotRecommendation{
					Label:       "Dispatch workflows",
					Description: "actions:write scope available",
					Command:     "pivot dispatch",
					Priority:    2,
				})
				break
			}
		}

	case "github_app_token":
		recs = append(recs, PivotRecommendation{
			Label:       "List app installations",
			Description: "App token may access multiple repos",
			Command:     "pivot github",
			Priority:    1,
		})

	case "github_app_key":
		recs = append(recs, PivotRecommendation{
			Label:       "Exchange PEM for installation token",
			Description: "GitHub App private key detected",
			Command:     "pivot app",
			Priority:    1,
		})

	case "aws_access_key", "aws_secret":
		recs = append(recs, PivotRecommendation{
			Label:       "List S3 buckets",
			Description: "AWS credentials detected",
			Command:     "order exec aws s3 ls",
			Priority:    1,
		}, PivotRecommendation{
			Label:       "Check STS identity",
			Description: "Determine account and role",
			Command:     "order exec aws sts get-caller-identity",
			Priority:    2,
		})

	case "azure":
		recs = append(recs, PivotRecommendation{
			Label:       "List resource groups",
			Description: "Azure credentials detected",
			Command:     "order exec az group list",
			Priority:    1,
		})

	case "gcp":
		recs = append(recs, PivotRecommendation{
			Label:       "List GCP projects",
			Description: "GCP credentials detected",
			Command:     "order exec gcloud projects list",
			Priority:    1,
		})

	case "npm":
		recs = append(recs, PivotRecommendation{
			Label:       "Check npm identity",
			Description: "Supply chain pivot possible",
			Command:     "order exec npm whoami",
			Priority:    1,
		})

	case "signing_key":
		recs = append(recs, PivotRecommendation{
			Label:       "Sign commits/artifacts",
			Description: "Signing key captured",
			Command:     "",
			Priority:    3,
		})
	}

	return recs
}
