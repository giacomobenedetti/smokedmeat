# Changelog

All notable changes to SmokedMeat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-04-01

### Added
- Public private-beta packaging for the repo: changelog, issue templates, and pull request template
- Public-facing feature reference in `docs/FEATURES.md`
- Whooli playground guide in `docs/WHOOLI.md`

### Changed
- Reworked the README for first-time operators, including quickstart, deployment modes, and public evaluation guidance
- Renamed the playground target to `whooli`
- Removed internal planning docs that are not meant to ship in the public repo

## [0.0.4] - 2026-03-27

### Added
- End-to-end GitHub Actions cache-poisoning flow with wizard UX, exact-key prediction, and persistent implant support
- Additional goat validation around the writer and victim workflow chain

## [0.0.3] - 2026-03-17

### Added
- SSH pivoting with `pivot ssh`, `pivot ssh org`, `pivot ssh org/repo`, and `ssh shell`
- Cloud post-exploit improvements with durable sessions, `cloud shell`, `cloud export`, and provider quick checks

## [0.0.2] - 2026-02-20

### Added
- GitHub App key pivot from PEM to installation token
- Workflow `if:` gate detection with trigger classification
- Issue deploy comment-mode for `issue_comment` vulnerabilities
- Draft PR support and auto-close on callback
- Server-side dispatch permission pre-checks

### Changed
- Migrated the Counter TUI to Bubble Tea v2 with Ultraviolet layout and compositing
- Split the monolithic `update.go` flow into focused subject files

## [0.0.1] - 2026-01-06

### Added
- Core Counter, Kitchen, and Brisket operator flow for GitHub Actions
- LOTP delivery support for CI/CD payload injection
- Kitchen-side GitHub API proxying
- Docker quickstart flow for local evaluation
- Attack graph browser view and E2E foundation
