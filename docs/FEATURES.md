# SmokedMeat Features

Detailed reference for every capability in the framework. For a high-level overview, see the [README](../README.md).

## Reconnaissance

The Brisket implant auto-detects the CI platform it's running on and collects environment details, secrets, OIDC token availability, runner metadata, and network egress capabilities.

For the first public release, SmokedMeat is intentionally scoped to GitHub Actions. The non-GitHub detections below are useful for runner classification and recon notes, but the supported analysis, delivery, exploit, token-pivot, cache-poisoning, and cloud-pivot workflows are GitHub Actions only in `v0.1.0`.

| Platform | Detection | Public `v0.1.0` Support |
|----------|-----------|-------------------------|
| GitHub Actions | `GITHUB_ACTIONS=true` | Full support |
| GitLab CI | `GITLAB_CI=true` | Recon classification only |
| Azure DevOps | `TF_BUILD=True` | Recon classification only |
| CircleCI | `CIRCLECI=true` | Recon classification only |
| Jenkins | `JENKINS_URL` | Recon classification only |
| Bitbucket Pipelines | `BITBUCKET_BUILD_NUMBER` | Recon classification only |

The `recon` command also classifies secrets found in environment variables by type (AWS keys, GitHub tokens, GCP service accounts, Slack tokens, database URLs, generic API keys, etc.) and probes for OIDC provider availability (AWS, GCP, Azure).

## Runner Secret Extraction (gump)

On Linux runners, the `env` command goes beyond `os.Environ()` by scanning the GitHub Actions Runner.Worker process memory via `/proc/<pid>/mem`. This recovers the full unmasked values of `secrets.*` and `vars.*` that GitHub normally masks in logs, along with the `GITHUB_TOKEN` and its fine-grained permission map.

## Vulnerability Analysis

SmokedMeat embeds [poutine](https://github.com/boostsecurityio/poutine) for static analysis of GitHub Actions workflows. The `analyze` command sends a target org or repo to the Kitchen, which clones and scans it for:

- **Injection vulnerabilities**  - Untrusted input (`github.event.pull_request.title`, `github.event.issue.body`, etc.) flowing into `run:` blocks or `actions/github-script`
- **Dangerous triggers**  - `pull_request_target`, `issue_comment`, `workflow_run` with unsafe checkout patterns
- **Workflow `if:` gate detection**  - Classifies gate conditions (e.g., `contains(github.event.comment.body, '/deploy')`) into trigger types with extracted trigger strings

Results populate the attack tree: org > repo > workflow > job > vulnerability.

The `deep-analyze` command adds Gitleaks-based secret scanning (private keys, GitHub PATs, fine-grained PATs, PKCS#12 files) across the repository's git history.

## Delivery Methods

The exploit wizard supports 5 automated delivery methods plus 2 manual fallbacks, selected based on the vulnerability type:

| Method | How it works |
|--------|-------------|
| **Create PR** | Fork the repo, push a branch with the stager payload, open a PR to trigger `pull_request_target` workflows. Supports draft PRs and auto-close on callback. |
| **Create Issue** | Open an issue with the payload in the title/body to trigger `issues`-triggered workflows. Supports auto-close on callback. |
| **Add Comment** | Comment on an existing issue or PR to trigger `issue_comment`-triggered workflows. Can target issues, existing PRs, or create a stub PR. |
| **LOTP** | Fork the repo, inject a Living Off The Pipeline payload into a build config file, and open a PR. |
| **Trigger Dispatch** | Send a `workflow_dispatch` event with the payload. Includes server-side preflight validation (workflow existence, required inputs). |
| **Copy Only** | Copy the stager payload to clipboard for manual delivery. |
| **Manual Steps** | Display step-by-step instructions. |

Each deployment registers a stager URL on the Kitchen. When the stager executes in the CI runner, it downloads the Brisket binary and starts beaconing.

## Injection Payloads (Rye)

The `inject` command generates context-aware injection payloads for 8 GitHub Actions injection vectors:

| Context | Constraints | Techniques |
|---------|-------------|------------|
| `git_branch` | 250 chars, no spaces/special chars | `$IFS`-separated substitution |
| `pr_title` | 256 chars, single line | Backtick/`$()` substitution, pipe/chain injection |
| `pr_body` | 64KB, multiline | Newline injection, quote breaking |
| `commit_message` | 72 chars first line | Substitution, chaining |
| `issue_title` | 256 chars, single line | Same as `pr_title` |
| `issue_body` | 64KB, multiline | Same as `pr_body` |
| `github_script` | Unlimited, JavaScript | Template literal escape, `child_process.execSync`, `process.mainModule` sandbox bypass |
| `bash_run` | Unlimited, bash | All bash techniques |

## Living Off The Pipeline (LOTP)

The LOTP catalog covers 15 build tools that execute code during install, build, or test phases:

npm, Yarn, pip, Bundler, Cargo, Go (`go generate`), Make, Docker, ESLint, Prettier, Jest, Gradle, Maven, Composer, pre-commit, Husky

Each entry includes the config files that enable the technique, the commands that trigger it, and example payloads. The `lotp` delivery method injects these payloads into the appropriate config file via a forked PR.

## Cache Poisoning

SmokedMeat can poison GitHub Actions caches to achieve persistence across workflow runs. The cache poisoning module:

- **Classifies writer eligibility**  - Determines which vulnerabilities can write to the cache (requires a trigger that runs attacker-controlled code)
- **Collects victim candidates**  - Identifies downstream workflows that restore from the same cache keys (`actions/setup-go`, `actions/cache`, etc.)
- **Computes exact cache keys**  - Predicts the cache key using the same hash algorithm GitHub uses (Go version + `go.sum` hash, or explicit key patterns)
- **Stages replacement entries**  - Builds a poisoned cache archive and uploads it via the Actions Cache API

The wizard walks the operator through selecting a writer vulnerability, choosing a victim workflow, and deploying the poisoned cache with an armed implant.

## GitHub Token Enumeration

The `token-test` command probes the available GitHub token against API endpoints to enumerate its actual permissions: `repo`, `read:user`, `user:email`, `user:follow`, `read:ssh_signing_key`, `read:gpg_key`, `read:org`, `gist`, `actions`, `read:packages`. It also identifies the token type (classic PAT, fine-grained PAT, GitHub Actions token, OAuth, installation token) and lists accessible repositories and organizations.

## OIDC Cloud Pivots

When the implant runs on a GitHub Actions runner with OIDC configured, `oidc <provider>` extracts a federated token and `oidc pivot <provider>` uses it to authenticate to the cloud provider:

| Provider | Token Exchange | Post-Pivot Queries |
|----------|---------------|-------------------|
| **AWS** | `sts:AssumeRoleWithWebIdentity` | `sts:GetCallerIdentity`, S3 bucket listing, ECR repository listing |
| **GCP** | `sts.googleapis.com` + `iamcredentials` | Project listing, GCS bucket listing, caller identity |
| **Azure** | AAD token exchange | Subscription listing, resource group listing, storage accounts, ACR listing |
| **Kubernetes** | Direct OIDC token | Token extraction only |

## Cloud Post-Exploit (Counter)

After a successful OIDC pivot, the Counter provides:

- **Durable cloud sessions**  - Credentials persist locally across TUI restarts
- **`cloud shell`**  - Drop into a local shell with pre-configured cloud CLI credentials (`gcloud`, `aws`, `az`). For GCP, this bootstraps a local gcloud credential database with the OIDC access token.
- **`cloud export`**  - Print the shell `export` commands for the active cloud session
- **Provider quick checks**  - One-command enumeration (identity, buckets, projects, etc.) surfaced directly in the TUI

## SSH Pivoting

When the implant recovers an SSH private key (deploy key or user key) from secrets or memory:

- **`pivot ssh`**  - Test the key against the current target repo via `ssh -T git@github.com`
- **`pivot ssh org:<owner>`**  - Probe all known repos in an org for SSH access
- **`pivot ssh repo:<owner/repo>`**  - Probe a specific repo
- **`ssh shell`**  - Drop into a local shell with the SSH key loaded in a temporary `ssh-agent`, with helper scripts for `git clone` via SSH
- **`ssh status`**  - Show confirmed SSH access from the attack graph

Confirmed repo access (read-only vs read-write) is persisted into the Pantry graph labels.

## GitHub Token Pivoting

- **`pivot github [target]`**  - Use a captured PAT or `GITHUB_TOKEN` to list accessible repos, discover private repos, and find new attack surface. Discovered repos are automatically queued for analysis.
- **`pivot app [app_id]`**  - Exchange a captured GitHub App private key (PEM) for a JWT, then mint an installation token. The token inherits the App's installation permissions.

## Attack Graph (Pantry)

All discoveries feed into a persistent directed graph stored in BBolt:

- **Node types**  - Organizations, repositories, workflows, jobs, vulnerabilities, tokens, cloud resources, OIDC providers
- **Edge types**  - Contains, triggers, grants-access, pivots-to
- **Pivot rules**  - Automated suggestions based on node types and captured credentials
- **Browser visualization**  - Live Cytoscape.js graph at `/graph` with WebSocket updates as new nodes are discovered

## Operator Interface (Counter)

The Counter TUI provides:

- **Phase-aware workflow**  - Setup > Recon > Wizard > Waiting > Post-Exploit with context-sensitive commands at each phase
- **7-step setup wizard**  - Kitchen URL, SSH key selection, operator name, key deployment, GitHub PAT, target org/repo, and initial analysis
- **Attack tree navigation**  - Expandable org/repo/workflow/job/vuln hierarchy with keyboard navigation. Private repos are highlighted. Nodes link to GitHub via OSC 8 hyperlinks.
- **Exploit wizard**  - 3-step flow: select vulnerability, choose delivery method, configure options (draft PR, auto-close, dwell mode, comment target), deploy
- **Loot stash**  - Collected secrets organized by repository and workflow, with deduplication, source tracking, and one-key pivot recommendations
- **Omnibox search**  - Fuzzy search across repos, workflows, jobs, vulnerabilities, and loot items
- **Tab completion**  - Phase-aware, context-sensitive suggestions for commands, targets, and arguments
- **Activity log**  - Scrollable, timestamped event log with icons for success/warning/error/agent events
- **Help overlay**  - `?` or `help` shows all available commands for the current phase
- **Callbacks modal**  - Live view of all agent sessions with online/offline status

## Teamserver (Kitchen)

- **SSH challenge-response auth**  - Operators authenticate with SSH keys via a challenge/verify handshake. The Kitchen sends a nonce, the Counter signs it with the operator's SSH key.
- **Shared-token auth**  - Quickstart and E2E environments use a pre-shared `AUTH_TOKEN` for simplified setup
- **BBolt persistence**  - Sessions, attack graphs, operation history, known entities, and loot survive Kitchen restarts
- **NATS JetStream**  - Durable message bus between Kitchen and Brisket agents. Subjects: `smokedmeat.orders.<agent_id>`, `smokedmeat.coleslaw.<agent_id>`, `smokedmeat.beacon.<agent_id>`
- **GitHub API proxy**  - All GitHub API calls are proxied through Kitchen. Counter makes zero direct GitHub API calls. This keeps tokens server-side.
- **Auto-TLS**  - Caddy reverse proxy with automatic Let's Encrypt certificates for self-hosted deployments
- **Stager registration**  - Kitchen generates unique stager URLs (`/r/{stagerID}`) that serve the Brisket binary on first callback
- **Operation history**  - Tracks analysis runs, deployments, and pivot operations with timestamps
- **Live graph endpoint**  - `/graph` serves a Cytoscape.js visualization page; `/graph/ws` pushes real-time updates via WebSocket
