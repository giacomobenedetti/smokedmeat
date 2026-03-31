// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActivityLog_New(t *testing.T) {
	log := NewActivityLog()

	assert.NotNil(t, log)
	assert.Empty(t, log.Entries())
}

func TestActivityLog_Add(t *testing.T) {
	log := NewActivityLog()

	log.Add(IconSuccess, "Test message")

	entries := log.Entries()
	assert.Len(t, entries, 1)
	assert.Equal(t, IconSuccess, entries[0].Icon)
	assert.Equal(t, "Test message", entries[0].Message)
}

func TestActivityLog_AddEntry(t *testing.T) {
	log := NewActivityLog()

	log.AddEntry(ActivityEntry{Icon: IconError, Message: "Error occurred"})

	entries := log.Entries()
	assert.Len(t, entries, 1)
	assert.Equal(t, IconError, entries[0].Icon)
}

func TestActivityLog_MaxEntries(t *testing.T) {
	log := NewActivityLog()

	// Add more than maxActivityEntries (100)
	for i := 0; i < 105; i++ {
		log.Add(IconInfo, "Message")
	}

	entries := log.Entries()
	assert.LessOrEqual(t, len(entries), 100, "Should not exceed max entries")
}

func TestActivityLog_Clear(t *testing.T) {
	log := NewActivityLog()
	log.Add(IconInfo, "Test")
	log.Add(IconInfo, "Test 2")

	log.Clear()

	assert.Empty(t, log.Entries())
}

func TestActivityLog_Render(t *testing.T) {
	log := NewActivityLog()
	log.Add(IconSuccess, "Operation completed")

	output := log.Render(80, 3, false)

	assert.Contains(t, output, "Operation completed")
	lines := strings.Split(output, "\n")
	assert.Equal(t, 3, len(lines), "Should pad to exact height")
}

func TestActivityLog_Render_Empty(t *testing.T) {
	log := NewActivityLog()

	output := log.Render(80, 3, false)

	lines := strings.Split(output, "\n")
	assert.Equal(t, 3, len(lines), "Should pad even when empty")
}

func TestActivityLog_Render_Focused(t *testing.T) {
	log := NewActivityLog()
	log.Add(IconSuccess, "Test message")

	output := log.Render(80, 3, true)

	assert.Contains(t, output, "│", "Focused pane should have yellow indicator")
}

func TestActivityLog_Icons(t *testing.T) {
	icons := []string{IconInfo, IconSuccess, IconError, IconWarning, IconAgent, IconSecret}
	for _, icon := range icons {
		assert.NotEmpty(t, icon, "Icon should not be empty")
	}
}

func TestActivityLog_Last(t *testing.T) {
	log := NewActivityLog()
	log.Add(IconInfo, "First")
	log.Add(IconInfo, "Second")
	log.Add(IconInfo, "Third")

	last2 := log.Last(2)

	assert.Len(t, last2, 2)
	assert.Equal(t, "Second", last2[0].Message)
	assert.Equal(t, "Third", last2[1].Message)
}

func TestActivityLog_Last_MoreThanAvailable(t *testing.T) {
	log := NewActivityLog()
	log.Add(IconInfo, "Only one")

	last5 := log.Last(5)

	assert.Len(t, last5, 1)
}
