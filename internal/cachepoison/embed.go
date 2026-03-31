// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package cachepoison

import _ "embed"

var (
	//go:embed assets/actions-checkout/dist/utility.js
	actionsCheckoutHookJS string
)
