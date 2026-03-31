// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

func (m *Model) focusPane(pane PaneFocus) {
	m.focus = FocusSessions
	m.paneFocus = pane
	m.updateFocus()
}

func (m *Model) focusInputPane() {
	m.focus = FocusInput
	m.updateFocus()
}
