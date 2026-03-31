// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

const maxActivityEntries = 100

type ActivityLog struct {
	entries   []ActivityEntry
	scrollPos int
	cursor    int
}

func NewActivityLog() *ActivityLog {
	return &ActivityLog{
		entries: make([]ActivityEntry, 0, maxActivityEntries),
	}
}

func (l *ActivityLog) Add(icon, message string) {
	entry := ActivityEntry{
		Timestamp: time.Now(),
		Icon:      icon,
		Message:   message,
	}
	l.entries = append(l.entries, entry)
	if len(l.entries) > maxActivityEntries {
		l.entries = l.entries[1:]
	}
	l.scrollToBottom()
}

func (l *ActivityLog) AddEntry(e ActivityEntry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	l.entries = append(l.entries, e)
	if len(l.entries) > maxActivityEntries {
		l.entries = l.entries[1:]
	}
	l.scrollToBottom()
}

func (l *ActivityLog) Sort() {
	sort.SliceStable(l.entries, func(i, j int) bool {
		return l.entries[i].Timestamp.Before(l.entries[j].Timestamp)
	})
	l.scrollToBottom()
}

func (l *ActivityLog) scrollToBottom() {
	l.cursor = len(l.entries) - 1
	if l.cursor < 0 {
		l.cursor = 0
	}
}

func (l *ActivityLog) Entries() []ActivityEntry {
	return l.entries
}

func (l *ActivityLog) Len() int {
	return len(l.entries)
}

func (l *ActivityLog) Last(n int) []ActivityEntry {
	if n >= len(l.entries) {
		return l.entries
	}
	return l.entries[len(l.entries)-n:]
}

func (l *ActivityLog) Clear() {
	l.entries = l.entries[:0]
	l.scrollPos = 0
}

func (l *ActivityLog) CursorUp() {
	if l.cursor > 0 {
		l.cursor--
	}
}

func (l *ActivityLog) CursorDown() {
	if l.cursor < len(l.entries)-1 {
		l.cursor++
	}
}

func (l *ActivityLog) Render(width, maxLines int, focused bool) string {
	var lines []string
	selectedLineIdx := -1

	if len(l.entries) == 0 {
		lines = append(lines, " "+mutedColor.Render("No activity yet"))
	} else {
		if l.cursor < l.scrollPos {
			l.scrollPos = l.cursor
		}
		if l.cursor >= l.scrollPos+maxLines {
			l.scrollPos = l.cursor - maxLines + 1
		}

		start := l.scrollPos
		end := start + maxLines
		if end > len(l.entries) {
			end = len(l.entries)
		}

		now := time.Now()
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		for i := start; i < end; i++ {
			e := l.entries[i]
			ts := formatActivityTimestamp(e.Timestamp, today)
			isSelected := focused && i == l.cursor
			var line string
			if isSelected {
				line = " " + ts + " " + e.Icon + " " + e.Message
			} else {
				line = " " + mutedColor.Render(ts) + " " + colorIcon(e.Icon) + " " + e.Message
			}
			if lipgloss.Width(line) > width-2 {
				line = truncateVisual(line, width-2)
			}
			if isSelected {
				selectedLineIdx = len(lines)
				lines = append(lines, treeSelectedStyle.Render(line))
			} else {
				lines = append(lines, line)
			}
		}
	}

	scroll := ScrollInfo{
		TotalLines:   len(l.entries),
		ViewportSize: maxLines,
		ScrollOffset: l.scrollPos,
	}
	selectedSet := make(map[int]bool)
	if selectedLineIdx >= 0 {
		selectedSet[selectedLineIdx] = true
	}
	return strings.Join(applyScrollIndicator(lines, maxLines, focused, selectedSet, scroll), "\n")
}

func formatActivityTimestamp(t, today time.Time) string {
	t = t.Local()
	if t.Before(today) {
		return t.Format("Jan 2 15:04")
	}
	return t.Format("15:04:05")
}

const (
	IconAgent     = "⚡"
	IconSecret    = "🔑"
	IconScan      = "◎"
	IconPivot     = "→"
	IconError     = "✗"
	IconSuccess   = "✓"
	IconWarning   = "⚠"
	IconInfo      = "●"
	IconEphemeral = "⏱"
)

func colorIcon(icon string) string {
	switch icon {
	case IconSuccess:
		return successColor.Render(icon)
	case IconError:
		return errorColor.Render(icon)
	case IconWarning:
		return warningColor.Render(icon)
	case IconAgent:
		return secondaryColorStyle.Render(icon)
	case IconSecret, IconEphemeral:
		return warningColor.Render(icon)
	case IconScan, IconInfo:
		return mutedColor.Render(icon)
	case IconPivot:
		return successColor.Render(icon)
	default:
		return icon
	}
}
