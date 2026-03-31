// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func (m *Model) renderKillChainOverlay(background string, height int) string {
	if m.killChainVM == nil {
		return background
	}

	modalWidth := m.width * 85 / 100
	if modalWidth < 60 {
		modalWidth = m.width - 4
	}
	if modalWidth > m.width-4 {
		modalWidth = m.width - 4
	}
	modalHeight := height - 4
	if modalHeight > 36 {
		modalHeight = 36
	}
	if modalHeight < 16 {
		modalHeight = 16
	}

	modalLines := m.buildKillChainModal(modalWidth, modalHeight)
	modal := strings.Join(modalLines, "\n")
	result := compositeCenter(modal, dimBackground(background), m.width, height)
	lines := strings.Split(result, "\n")
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", m.width))
	}
	return strings.Join(lines[:height], "\n")
}

func (m *Model) buildKillChainModal(width, height int) []string {
	var lines []string

	bTop := modalBorderStyle.Render("┌" + strings.Repeat("─", width-2) + "┐")
	bLeft := modalBorderStyle.Render("│")
	bRight := modalBorderStyle.Render("│")
	bBottom := modalBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")
	bSep := modalBorderStyle.Render("─")

	lines = append(lines, bTop)

	title := " KILL CHAIN: " + m.killChainVM.VulnLabel
	innerWidth := width - 2
	if lipgloss.Width(title) > innerWidth {
		title = truncateVisual(title, innerWidth)
	}
	titleContent := title + strings.Repeat(" ", innerWidth-lipgloss.Width(title))
	styledTitle := modalTitleStyle.Width(innerWidth).Render(titleContent)
	lines = append(lines,
		bLeft+styledTitle+bRight,
		bLeft+strings.Repeat(" ", innerWidth)+bRight,
	)

	contentLines := m.buildKillChainContent(innerWidth)

	visibleHeight := height - 6
	scrollPos := m.killChainVM.ScrollPos
	if scrollPos > len(contentLines)-visibleHeight {
		scrollPos = len(contentLines) - visibleHeight
	}
	if scrollPos < 0 {
		scrollPos = 0
	}
	m.killChainVM.ScrollPos = scrollPos

	endIdx := scrollPos + visibleHeight
	if endIdx > len(contentLines) {
		endIdx = len(contentLines)
	}

	for i := scrollPos; i < endIdx; i++ {
		if len(lines) >= height-3 {
			break
		}
		lines = append(lines, bLeft+contentLines[i]+bRight)
	}

	for len(lines) < height-3 {
		lines = append(lines, bLeft+strings.Repeat(" ", innerWidth)+bRight)
	}

	hints := helpKeyStyle.Render("Esc/K") + helpDescStyle.Render(":close  ") +
		helpKeyStyle.Render("j/k") + helpDescStyle.Render(":scroll")
	hintsWidth := lipgloss.Width(hints)
	hintsPadding := innerWidth - 2 - hintsWidth
	if hintsPadding < 0 {
		hintsPadding = 0
	}
	lines = append(lines,
		bLeft+" "+strings.Repeat(bSep, innerWidth-2)+" "+bRight,
		bLeft+" "+hints+strings.Repeat(" ", hintsPadding)+" "+bRight,
		bBottom,
	)

	for i, line := range lines {
		visualWidth := lipgloss.Width(line)
		if visualWidth < width {
			lines[i] = line + strings.Repeat(" ", width-visualWidth)
		}
	}

	return lines
}

func (m *Model) buildKillChainContent(innerWidth int) []string {
	var lines []string
	emptyLine := strings.Repeat(" ", innerWidth)
	chain := m.killChainVM.Chain
	prereq := m.killChainVM.Prereq

	for i, stage := range chain.Stages {
		if stage.StageType == pantry.StageCredential {
			continue
		}

		if stage.StageType == pantry.StageExploit && prereq != nil {
			lines = append(lines, m.renderPrereqLines(prereq, innerWidth)...)
			connector := "  │"
			pad := innerWidth - lipgloss.Width(connector)
			if pad < 0 {
				pad = 0
			}
			lines = append(lines, connector+strings.Repeat(" ", pad))
		}

		stageLabel := stageTypeLabel(stage)
		assetLabel := stageAssetLabel(stage)
		badge := stageStatusBadge(stage)
		if stage.StageType == pantry.StageExploit && prereq != nil {
			badge = exploitBadgeWithPrereq(stage, prereq)
		}

		line := fmt.Sprintf("  %s  %-10s %s %s", stageIcon(stage), stageLabel, assetLabel, badge)
		pad := innerWidth - lipgloss.Width(line)
		if pad < 0 {
			pad = 0
		}
		lines = append(lines, line+strings.Repeat(" ", pad))

		isLast := true
		for j := i + 1; j < len(chain.Stages); j++ {
			if chain.Stages[j].StageType != pantry.StageCredential {
				isLast = false
				break
			}
		}
		if !isLast {
			connector := "  │"
			pad = innerWidth - lipgloss.Width(connector)
			if pad < 0 {
				pad = 0
			}
			lines = append(lines, connector+strings.Repeat(" ", pad))
		}
	}

	var credStages []pantry.KillChainStage
	for _, stage := range chain.Stages {
		if stage.StageType == pantry.StageCredential {
			credStages = append(credStages, stage)
		}
	}

	if len(credStages) > 0 {
		lines = append(lines, emptyLine)

		for _, stage := range credStages {
			assetLabel := stageAssetLabel(stage)
			statusBadge := stageStatusBadge(stage)
			icon := stageIcon(stage)

			line := fmt.Sprintf("  %s  LOOT       %s %s", icon, assetLabel, statusBadge)
			pad := innerWidth - lipgloss.Width(line)
			if pad < 0 {
				pad = 0
			}
			lines = append(lines, line+strings.Repeat(" ", pad))
		}
	}

	if len(chain.Projections) > 0 {
		lines = append(lines, emptyLine)

		sepLine := "  " + strings.Repeat("─", 3) + " PIVOT TARGETS " + strings.Repeat("─", 3)
		sepStyle := mutedColor.Render(sepLine)
		pad := innerWidth - lipgloss.Width(sepStyle)
		if pad < 0 {
			pad = 0
		}
		lines = append(lines, sepStyle+strings.Repeat(" ", pad))

		for _, proj := range chain.Projections {
			for _, action := range proj.Actions {
				providerNote := ""
				if proj.Provider != "" {
					providerNote = " (" + proj.CredentialName + ")"
				}
				line := warningColor.Render("  → ") + action + mutedColor.Render(providerNote)
				pad := innerWidth - lipgloss.Width(line)
				if pad < 0 {
					pad = 0
				}
				lines = append(lines, line+strings.Repeat(" ", pad))
			}
		}
	}

	return lines
}

func stageIcon(stage pantry.KillChainStage) string {
	if stage.Confirmed {
		return successColor.Render("◉")
	}
	return warningColor.Render("◉")
}

func stageTypeLabel(stage pantry.KillChainStage) string {
	switch stage.Asset.Type {
	case pantry.AssetOrganization:
		return "ENTRY"
	case pantry.AssetRepository:
		return "REPO"
	case pantry.AssetWorkflow:
		return "WORKFLOW"
	case pantry.AssetJob:
		return "JOB"
	case pantry.AssetVulnerability:
		return "EXPLOIT"
	case pantry.AssetSecret:
		return "LOOT"
	case pantry.AssetToken:
		return "LOOT"
	default:
		return strings.ToUpper(string(stage.Asset.Type))
	}
}

func stageAssetLabel(stage pantry.KillChainStage) string {
	a := stage.Asset
	switch a.Type {
	case pantry.AssetOrganization:
		return a.Name
	case pantry.AssetRepository:
		org, _ := a.Properties["org"].(string)
		repo, _ := a.Properties["repo"].(string)
		if org != "" && repo != "" {
			return org + "/" + repo
		}
		return a.Name
	case pantry.AssetWorkflow:
		path, _ := a.Properties["path"].(string)
		if path != "" {
			return path
		}
		return a.Name
	case pantry.AssetJob:
		return a.Name
	case pantry.AssetVulnerability:
		title, _ := a.Properties["title"].(string)
		if title != "" {
			return title
		}
		return formatRuleID(a.RuleID)
	case pantry.AssetSecret:
		return a.Name
	case pantry.AssetToken:
		tokenType, _ := a.Properties["token_type"].(string)
		scopes := a.StringSliceProperty("scopes")
		if len(scopes) > 0 {
			return tokenType + " (" + strings.Join(scopes, ", ") + ")"
		}
		return tokenType
	default:
		return a.Name
	}
}

func stageStatusBadge(stage pantry.KillChainStage) string {
	if stage.Confirmed {
		return successColor.Render("[CONFIRMED]")
	}
	switch stage.StageType {
	case pantry.StageEntry:
		return ""
	case pantry.StageCredential:
		return mutedColor.Render("[PROJECTED]")
	default:
		return mutedColor.Render("[THEORETICAL]")
	}
}

func exploitBadgeWithPrereq(stage pantry.KillChainStage, prereq *Prerequisite) string {
	if stage.Confirmed {
		return successColor.Render("[CONFIRMED]")
	}
	if prereq.Status == PrereqNotMet {
		return warningColor.Render("[BLOCKED]")
	}
	return successColor.Render("[READY]")
}

func (m *Model) renderPrereqLines(prereq *Prerequisite, innerWidth int) []string {
	var lines []string

	var icon, label, badge string
	if prereq.Status == PrereqMet {
		icon = successColor.Render("✓")
		label = fmt.Sprintf("actions:write on %s", prereq.Target)
		badge = successColor.Render("[FROM LOOT: " + prereq.Source + "]")
		if strings.HasPrefix(prereq.Source, "operator PAT") {
			badge = successColor.Render("[OPERATOR PAT]")
		}
	} else {
		icon = warningColor.Render("⚠")
		label = fmt.Sprintf("actions:write on %s", prereq.Target)
		badge = warningColor.Render("[NOT MET]")
	}

	line := fmt.Sprintf("  %s  %-10s %s %s", icon, "REQUIRES", label, badge)
	lines = append(lines, fitLine(line, innerWidth))

	if prereq.Status == PrereqNotMet && prereq.Hint != "" {
		hintPrefix := "             → "
		maxHint := innerWidth - lipgloss.Width(mutedColor.Render(hintPrefix)) - 1
		hint := truncateVisual(prereq.Hint, maxHint)
		hintLine := mutedColor.Render(hintPrefix + hint)
		lines = append(lines, fitLine(hintLine, innerWidth))
	}

	return lines
}

func fitLine(line string, innerWidth int) string {
	pad := innerWidth - lipgloss.Width(line)
	if pad > 0 {
		return line + strings.Repeat(" ", pad)
	}
	return line
}
