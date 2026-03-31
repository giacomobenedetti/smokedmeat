// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

const persistentCallbackDefaultDwell = 15 * time.Minute

func cachePoisonPersistentDwell(duration time.Duration) time.Duration {
	if duration > 0 {
		return duration
	}
	return persistentCallbackDefaultDwell
}

func (m *Model) openCallbacksModal() tea.Cmd {
	m.prevView = m.view
	m.prevFocus = m.focus
	m.view = ViewCallbacks
	return m.fetchCallbacksCmd()
}

func (m Model) fetchCallbacksCmd() tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return CallbackFetchErrorMsg{Err: fmt.Errorf("not connected to kitchen")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		callbacks, err := m.kitchenClient.FetchCallbacks(ctx, m.config.SessionID)
		if err != nil {
			return CallbackFetchErrorMsg{Err: err}
		}
		return CallbacksFetchedMsg{Callbacks: callbacks}
	}
}

func (m Model) controlCallbackCmd(callbackID, action string) tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return CallbackControlFailedMsg{CallbackID: callbackID, Action: action, Err: fmt.Errorf("not connected to kitchen")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		callback, err := m.kitchenClient.ControlCallback(ctx, callbackID, counter.CallbackControlRequest{Action: action})
		if err != nil {
			return CallbackControlFailedMsg{CallbackID: callbackID, Action: action, Err: err}
		}
		return CallbackControlSuccessMsg{Action: action, Callback: *callback}
	}
}

func (m *Model) setCallbacks(callbacks []counter.CallbackPayload) {
	slices.SortFunc(callbacks, func(a, b counter.CallbackPayload) int {
		aTime := a.CreatedAt
		if a.CallbackAt != nil {
			aTime = *a.CallbackAt
		}
		bTime := b.CreatedAt
		if b.CallbackAt != nil {
			bTime = *b.CallbackAt
		}
		switch {
		case aTime.After(bTime):
			return -1
		case aTime.Before(bTime):
			return 1
		default:
			return strings.Compare(a.ID, b.ID)
		}
	})
	m.callbacks = callbacks
	if m.callbackModal == nil {
		m.callbackModal = &CallbackModalState{}
	}
	if len(m.callbacks) == 0 {
		m.callbackModal.Cursor = 0
		return
	}
	if m.callbackModal.Cursor >= len(m.callbacks) {
		m.callbackModal.Cursor = len(m.callbacks) - 1
	}
	if m.callbackModal.Cursor < 0 {
		m.callbackModal.Cursor = 0
	}
}

func (m *Model) upsertCallback(callback counter.CallbackPayload) {
	for i := range m.callbacks {
		if m.callbacks[i].ID == callback.ID {
			m.callbacks[i] = callback
			m.setCallbacks(m.callbacks)
			return
		}
	}
	m.callbacks = append(m.callbacks, callback)
	m.setCallbacks(m.callbacks)
}

func (m *Model) noteCallbackHit(callbackID, agentID, mode string, when time.Time) {
	if callbackID == "" {
		return
	}
	for i := range m.callbacks {
		if m.callbacks[i].ID != callbackID {
			continue
		}
		callbackAt := when
		m.callbacks[i].CalledBack = true
		m.callbacks[i].CallbackAt = &callbackAt
		m.callbacks[i].LastAgentID = agentID
		m.callbacks[i].CallbackCount++
		if mode != "" {
			m.callbacks[i].NextMode = ""
		}
		m.setCallbacks(m.callbacks)
		return
	}
}

func (m Model) selectedCallback() *counter.CallbackPayload {
	if len(m.callbacks) == 0 || m.callbackModal == nil {
		return nil
	}
	cursor := m.callbackModal.Cursor
	if cursor < 0 || cursor >= len(m.callbacks) {
		return nil
	}
	callback := m.callbacks[cursor]
	return &callback
}

func (m *Model) callbackCursorDown() {
	if len(m.callbacks) == 0 || m.callbackModal == nil {
		return
	}
	if m.callbackModal.Cursor < len(m.callbacks)-1 {
		m.callbackModal.Cursor++
	}
}

func (m *Model) callbackCursorUp() {
	if len(m.callbacks) == 0 || m.callbackModal == nil {
		return
	}
	if m.callbackModal.Cursor > 0 {
		m.callbackModal.Cursor--
	}
}

func (m *Model) recordCallbackAgent(callbackID, agentID, hostname, mode string, when time.Time) {
	if callbackID == "" || agentID == "" {
		return
	}
	links := m.callbackAgents[callbackID]
	for i := range links {
		if links[i].AgentID != agentID {
			continue
		}
		links[i].Hostname = hostname
		links[i].LastSeen = when
		if mode != "" {
			links[i].Mode = mode
		}
		m.callbackAgents[callbackID] = links
		return
	}
	links = append(links, CallbackAgentLink{
		AgentID:  agentID,
		Hostname: hostname,
		LastSeen: when,
		Mode:     mode,
	})
	slices.SortFunc(links, func(a, b CallbackAgentLink) int {
		switch {
		case a.LastSeen.After(b.LastSeen):
			return -1
		case a.LastSeen.Before(b.LastSeen):
			return 1
		default:
			return strings.Compare(a.AgentID, b.AgentID)
		}
	})
	m.callbackAgents[callbackID] = links
}

func (m *Model) recordCallbackSecrets(callbackID, agentID string, hits int) {
	if callbackID == "" || agentID == "" || hits <= 0 {
		return
	}
	links := m.callbackAgents[callbackID]
	for i := range links {
		if links[i].AgentID == agentID {
			links[i].SecretHits += hits
			m.callbackAgents[callbackID] = links
			return
		}
	}
}

func (m Model) handleCallbacksKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc", "q", "I", "shift+i", "C", "shift+c":
		m.view = m.prevView
		m.focus = m.prevFocus
		m.updateFocus()
		return m, nil
	case "j", "down":
		m.callbackCursorDown()
		return m, nil
	case "k", "up":
		m.callbackCursorUp()
		return m, nil
	case "r":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "revoke")
		}
	case "e":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "default_express")
		}
	case "d":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "default_dwell")
		}
	case "n":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "arm_next_dwell")
		}
	case "x":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "clear_next_override")
		}
	}
	return m, nil
}
