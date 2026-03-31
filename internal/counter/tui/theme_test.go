// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"image/color"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/stretchr/testify/assert"
)

func TestBestContrastColor_PrefersHighestContrastCandidate(t *testing.T) {
	bg := lipglossColor("#ff9e64")
	light := lipglossColor("#c0caf5")
	dark := lipglossColor("#1a1b26")

	best := bestContrastColor(bg, light, dark)

	assert.True(t, sameColor(best, dark))
	assert.Greater(t, contrastRatio(bg, dark), contrastRatio(bg, light))
}

func TestApplyTheme_UsesReadableModalTitleForeground(t *testing.T) {
	for _, name := range ThemeNames() {
		t.Run(string(name), func(t *testing.T) {
			p := themes[name]
			chosen := bestContrastColor(p.Primary, p.Fg, p.Base)

			assert.GreaterOrEqual(t, contrastRatio(p.Primary, chosen), contrastRatio(p.Primary, p.Fg))
		})
	}
}

func lipglossColor(hex string) color.Color {
	return lipgloss.Color(hex)
}

func sameColor(a, b color.Color) bool {
	ar, ag, ab, aa := a.RGBA()
	br, bg, bb, ba := b.RGBA()
	return ar == br && ag == bg && ab == bb && aa == ba
}
