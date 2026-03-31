---
name: e2e
description: Run end-to-end tests of SmokedMeat against the Whooli goat repos. Use when testing TUI changes, verifying exploit flows, debugging UI state, or validating Kitchen/Counter integration.
allowed-tools: Bash, Read, Grep, Glob
---

# E2E Testing

Run this skill to test SmokedMeat end-to-end. Infrastructure runs in Docker, TUI runs in tmux for capture.

## Configuration Isolation

E2E tests use `.claude/e2e/` for ALL configuration, NOT `~/.smokedmeat/`:

| File | Purpose |
|------|---------|
| `.claude/e2e/.env` | AUTH_TOKEN, KITCHEN_URL, GITHUB_TOKEN (generated/saved by `make e2e-smoke` / `make e2e-goat`) |
| `.claude/e2e/config.yaml` | Counter config (written by test) |
| `.claude/e2e/tokens.yaml` | Token vault (created automatically) |

The `SMOKEDMEAT_CONFIG_DIR=.claude/e2e` env var is set automatically by `make e2e-counter`.

## Testing Focus

**User requested:** $ARGUMENTS

If a focus was specified above, prioritize testing that specific area:
- **"wizard"** → Focus on setup wizard flow, step transitions, input validation
- **"layout"** → Focus on panel alignment, borders, resize behavior
- **"exploit"** → Focus on vulnerability selection, payload config, deployment
- **"recon"** → Focus on post-exploit phase, agent commands, loot display
- **"auth"** → Focus on Kitchen auth, token validation, API responses
- **General description** → Interpret and test the described scenario

If no focus specified or `$ARGUMENTS` is empty, start with the fast smoke test and only move to the GOAT test when the user wants the full chain.

## Fast Smoke Path

Run the automated Go test that handles everything end-to-end:

```bash
make e2e-smoke
```

This command handles the short public foothold lifecycle:
1. Prompts for `GITHUB_TOKEN` if not saved in `.claude/e2e/.env`
2. Tears down any running containers (`make e2e-down`)
3. Purges all state including Docker volumes and DB (`make e2e-purge`)
4. Starts fresh infrastructure (`make e2e-up`  - Docker + Cloudflare tunnel)
5. Waits 5s for tunnel DNS propagation
6. Runs `TestPublicExploitSmoke`, which:
   - Verifies Kitchen health via HTTP
   - Writes Counter config with the public `whooli/xyz` target
   - Starts Counter TUI in tmux
   - Waits for Recon
   - Deploys the easy public issue-body foothold
   - Waits for Brisket callback
   - Confirms operator loot is present
   - Closes the created issue on exit

## Full GOAT Path

Run the merged full-chain test:

```bash
make e2e-goat
```

This runs `TestGOATFlagPath`, which covers the real attack chain from public `xyz` initial access through:
- `workflow_dispatch` abuse to recover `WHOOLI_INT_PAT`
- PAT-driven repo visibility
- deep-analyze on `newcleus-core-v3`
- SSH pivot and `ssh shell`
- GitHub App pivot
- PR-driven cache poisoning on `infrastructure-definitions`
- victim deploy workflow trigger
- OIDC pivot to GCP
- `cloud shell`
- `flag.txt` retrieval from the bucket

### Typical Timings

| Phase | Duration |
|-------|----------|
| Infrastructure (down + purge + up + DNS wait) | ~30s |
| Health check | <2s |
| `e2e-smoke` total | ~45-90s |
| `e2e-goat` total | environment-dependent, typically several minutes |

### If the test passes

Report the results. No further action needed.

### If the test fails

The test output includes the tmux capture at the point of failure. Look at:
- Which `requireContent` call failed and what it expected vs what was captured
- Whether infrastructure is healthy (check the health check step)
- Whether the Counter compiled and started (check "counter did not produce output")

For manual debugging, the tmux session is still running:
```bash
make e2e-capture     # See current TUI state
make e2e-keys KEYS='Enter'  # Send input manually
```

## Manual Iteration Workflows

### TUI only (tunnel stays up):
```bash
make e2e-counter   # Restarts Counter in tmux
make e2e-capture   # See current state
```

### Kitchen changes:
```bash
make e2e-kitchen-rebuild   # Rebuild Kitchen image (tunnel stays)
make e2e-counter           # Restart Counter
```

### Sending Input:
```bash
make e2e-keys KEYS='whooli'
make e2e-keys KEYS='Enter'
make e2e-keys KEYS='Tab'
tmux send-keys -t smokedmeat-e2e C-c   # Ctrl combinations
```

## Common Failure Indicators

| Capture shows | Likely cause |
|---------------|-------------|
| "unauthorized" | Token mismatch  - AUTH_TOKEN in .env doesn't match Kitchen |
| "connection refused" | Kitchen not running or tunnel down |
| No yellow highlight | Focus lost bug in TUI |
| Truncated/overlapping panels | Layout bug  - check Stickers/overlay code |
| "ERROR:" in red | Application error in Counter |
| "no such host" | Tunnel DNS not propagated  - increase sleep or retry |

## Bug Tracking

Append to `docs/e2e-bugs.md`:
```markdown
## Bug #N: [title]
- **Severity:** LOW/MEDIUM/HIGH
- **Location:** [panel]
- **Description:** [issue]
- **Expected:** [correct behavior]
```

## Cleanup

```bash
make e2e-down    # Stop containers (keep volumes)
make e2e-purge   # Stop and delete all data (volumes + DB)
```

Issues created on whooli/xyz are automatically closed by `t.Cleanup()` in the test.
For manual cleanup:
```bash
gh issue close <number> -R whooli/xyz
```
