# Goal-Oriented Kill Chain Planning

## Why This Exists

SmokedMeat is already good at surfacing local next steps:

- find a vuln
- exploit it
- collect loot
- pivot to a stronger credential

What is still weak is planning across multiple pivots toward a specific end state.

The goat paths exposed the gap clearly:

- a GitHub App token may be enough for the main cache-poison path on a private repo
- an SSH deploy key may allow `git push` but not PR creation
- branch protection or rulesets may block direct writes to the default branch
- a GitHub App key or PAT may be needed to open the PR even if the SSH key is the best write path
- the operator may need to combine multiple credentials and repo-specific constraints to reach the actual goal

Today the operator has to infer too much of that manually.

## Product Direction

Add a new goal-oriented planning layer on top of the existing target and suggestion system.

Keep `set target` as the current scope selector.

Introduce a separate goal concept for the operator's intended end state, for example:

```text
set goal repo:whooli/infrastructure-definitions poison-deploy-cache
```

The goal should also be selectable interactively from the kill-chain modal, with a small guided flow rather than a raw command-only UX.

## Core Idea

When a goal is set, SmokedMeat should reason about:

- what the operator is trying to achieve
- what constraints apply to that repo or workflow
- what credentials and pivots can satisfy the missing prerequisites
- what the next best move is right now

This is not the same thing as `set target`.

- `set target` answers: what am I currently looking at or analyzing?
- `set goal` answers: where am I trying to end up?

Both should coexist.

## Missing Metadata That Would Help

The goat SSH path highlighted an important missing signal: repo write access alone is not enough.

SmokedMeat should ingest and surface repo control-plane metadata such as:

- branch protection state
- rulesets that block direct pushes or require PRs
- whether the default branch is writable by the current credential
- whether PR creation is available with the current credential

This metadata should be visible:

- when highlighting a repo node
- in graph mode
- in kill-chain reasoning

Small orgs can fetch this eagerly during `analyze`.
Large orgs may need optional or rate-aware fetching.

The important part is not exhaustive collection on day one; it is making branch and PR constraints visible enough to drive better reasoning.

## Kill Chain Implications

A goal-aware kill chain should be able to combine capabilities across pivots.

Example:

1. GitHub App token proves issue creation and workflow triggering on `infrastructure-definitions`
2. cache poisoning is directly reachable from the issue/comment writer workflow
3. the planner suggests the main wizard path for `deploy.yml`
4. the SSH key remains available as a separate way to trigger the tagged `release.yml` bonus path

This moves the kill chain from "what can I do with this one credential?" toward "what combination of capabilities reaches the chosen goal?"

## UX Shape

Candidate UX pieces:

- `set goal ...` command
- `K` kill-chain flow that asks for the intended end state
- goal persistence in `~/.smokedmeat/config.yaml`
- dynamic suggestions that stay aligned with the active goal
- repo-node metadata panels that explain why the planner prefers branch push, PR creation, token swap, or SSH pivot

The planner should be able to say things like:

- direct push blocked by branch protection
- PR creation required
- issue/comment writer already sufficient for cache poisoning
- current SSH key can write a side branch
- current App key can open the PR
- current SSH key can push a release tag after the cache is poisoned

## Relationship To Cache Poisoning

This is distinct from the cache-poisoning delivery work and its follow-up hardening.

Cache poisoning is a delivery capability.
Goal-oriented kill-chain planning is the reasoning and operator-guidance layer that helps the user discover why cache poisoning is the next move and what prerequisites are still missing.

## First Slice

Keep the first implementation narrow:

- GitHub only
- repo rules / branch protection metadata on analyzed repos
- one or two explicit goal types
- suggestions that react to the goal and known credential mix

Do not start with:

- a giant general-purpose planner
- every possible end goal
- every CI provider

## Done Criteria

This task is in good shape when:

- repo-level branch/PR constraints are visible in the TUI and graph
- kill-chain reasoning can explain why one credential is insufficient on its own
- the operator can set a goal separately from the active target
- dynamic suggestions become meaningfully better for multi-pivot paths such as the goat chain
