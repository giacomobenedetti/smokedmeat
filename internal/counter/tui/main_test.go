// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"os"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
)

func TestMain(m *testing.M) {
	lipgloss.Writer.Profile = colorprofile.Ascii
	os.Setenv("SMOKEDMEAT_CONFIG_DIR", fmt.Sprintf("%s/smokedmeat-test-%d", os.TempDir(), os.Getpid()))
	os.Exit(m.Run())
}
