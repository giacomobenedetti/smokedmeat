// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package cachepoison

import "strings"

func ReplacementKey(candidate VictimCandidate) string {
	return strings.TrimSpace(cacheEntryPlan(candidate).PredictedKey)
}

func ReplacementKeyPrefix(candidate VictimCandidate) string {
	plan := cacheEntryPlan(candidate)
	switch plan.Strategy {
	case StrategySetupGo:
		return "setup-go-"
	case StrategySetupNode:
		return "setup-node-"
	case StrategySetupPython:
		return "setup-python-"
	case StrategySetupJava:
		return "setup-java-"
	}

	keyTemplate := strings.TrimSpace(plan.KeyTemplate)
	if keyTemplate == "" {
		keyTemplate = strings.TrimSpace(candidate.KeyTemplate)
	}
	if keyTemplate == "" {
		return ""
	}
	if idx := strings.Index(keyTemplate, "${{"); idx != -1 {
		keyTemplate = keyTemplate[:idx]
	}
	return strings.TrimSpace(keyTemplate)
}
