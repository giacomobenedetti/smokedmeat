// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"context"

	"github.com/boostsecurityio/poutine/models"
)

// NoopFormatter is a no-op formatter that satisfies the analyze.Formatter interface.
// We process results directly rather than using poutine's built-in formatters.
type NoopFormatter struct{}

// Format does nothing - we handle results ourselves.
func (f *NoopFormatter) Format(_ context.Context, _ []*models.PackageInsights) error {
	return nil
}

// FormatWithPath does nothing - we handle results ourselves.
func (f *NoopFormatter) FormatWithPath(_ context.Context, _ []*models.PackageInsights, _ map[string][]*models.RepoInfo) error {
	return nil
}
