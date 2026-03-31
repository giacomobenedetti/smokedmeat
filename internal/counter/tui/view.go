// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func (m Model) View() tea.View {
	if !m.ready || m.width == 0 {
		return tea.View{}
	}
	var v tea.View
	switch {
	case m.quitting:
		v = tea.NewView("Goodbye!\n")
	default:
		v = tea.NewView(m.RenderStickersLayout())
	}
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.KeyboardEnhancements.ReportEventTypes = true
	v.WindowTitle = "SmokedMeat Counter"
	v.BackgroundColor = baseBgColor
	return v
}

func (m Model) renderInputPanel() string {
	prompt := promptStyle.Render("❯ ")

	// Use unfocused style when modal is active
	isModalActive := m.view.IsModal()
	style := inputStyle
	if m.focus == FocusInput && !isModalActive {
		style = inputFocusedStyle
	}

	var sessionIndicator string
	if session := m.SelectedSession(); session != nil {
		sessionIndicator = secondaryColorStyle.Render("[" + truncate(session.AgentID, 12) + "] ")
	}

	// Show static text (no cursor) when modal is active
	var inputContent string
	if isModalActive {
		inputContent = mutedColor.Render(m.input.Value())
	} else {
		inputContent = m.input.View()
	}

	inputLine := sessionIndicator + prompt + inputContent

	if m.completionHint != "" && !isModalActive {
		hint := mutedColor.Render("  " + m.completionHint)
		inputLine = inputLine + "\n" + hint
	}

	return style.Width(m.width - 4).Render(inputLine)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func truncateVisual(s string, maxWidth int) string {
	if lipgloss.Width(s) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return "..."
	}
	for i := range s {
		if lipgloss.Width(s[:i]) > maxWidth-3 {
			if i > 0 {
				return s[:i-1] + "..."
			}
			return "..."
		}
	}
	return s
}
