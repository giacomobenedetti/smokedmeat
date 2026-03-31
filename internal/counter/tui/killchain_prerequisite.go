// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type PrereqStatus int

const (
	PrereqMet PrereqStatus = iota
	PrereqNotMet
)

type Prerequisite struct {
	Scope  string
	Target string
	Status PrereqStatus
	Source string
	Hint   string
}

func (m *Model) detectPrerequisites(chain pantry.KillChain) *Prerequisite {
	var exploitStage *pantry.KillChainStage
	for i := range chain.Stages {
		if chain.Stages[i].StageType == pantry.StageExploit {
			exploitStage = &chain.Stages[i]
			break
		}
	}
	if exploitStage == nil {
		return nil
	}

	if !hasWorkflowDispatchTrigger(exploitStage.Asset) {
		return nil
	}

	target := extractTargetRepo(chain)

	prereq := &Prerequisite{
		Scope:  "actions:write",
		Target: target,
	}

	if secret := findActionsWriteToken(m.lootStash); secret != nil {
		prereq.Status = PrereqMet
		prereq.Source = secret.Name + " (loot)"
		return prereq
	}
	if secret := findLiveActionsWriteToken(m.sessionLoot, m.tokenPermissions); secret != nil {
		prereq.Status = PrereqMet
		prereq.Source = secret.Name + " (active session)"
		return prereq
	}

	if m.tokenInfo != nil {
		if m.tokenInfo.HasScope("repo") {
			prereq.Status = PrereqMet
			prereq.Source = "operator PAT (repo scope)"
			return prereq
		}
		if m.tokenInfo.HasScope("actions:write") {
			prereq.Status = PrereqMet
			prereq.Source = "operator PAT (actions:write)"
			return prereq
		}
	}

	prereq.Status = PrereqNotMet
	prereq.Hint = m.buildPrereqHint(target)
	return prereq
}

func findActionsWriteToken(secrets []CollectedSecret) *CollectedSecret {
	for i := range secrets {
		if secretHasActionsWrite(secrets[i]) {
			return &secrets[i]
		}
	}
	return nil
}

func extractTargetRepo(chain pantry.KillChain) string {
	for _, stage := range chain.Stages {
		if stage.Asset.Type == pantry.AssetRepository {
			org, _ := stage.Asset.Properties["org"].(string)
			repo, _ := stage.Asset.Properties["repo"].(string)
			if org != "" && repo != "" {
				return org + "/" + repo
			}
			return stage.Asset.Name
		}
	}
	return ""
}

func (m *Model) buildPrereqHint(targetRepo string) string {
	for _, v := range m.vulnerabilities {
		if v.Repository != targetRepo {
			continue
		}
		switch v.Trigger {
		case "issue_comment", "issues", "pull_request_target":
			return fmt.Sprintf("Use %s vuln, dwell to capture token", v.Trigger)
		}
	}
	return "Pivot through another vuln for actions:write"
}

func hasWorkflowDispatchTrigger(a pantry.Asset) bool {
	if triggers := a.StringSliceProperty("event_triggers"); len(triggers) > 0 {
		for _, t := range triggers {
			if t == "workflow_dispatch" {
				return true
			}
		}
		return false
	}
	if trigger, ok := a.Properties["trigger"].(string); ok {
		for _, t := range strings.Split(trigger, ", ") {
			if strings.TrimSpace(t) == "workflow_dispatch" {
				return true
			}
		}
	}
	return false
}
