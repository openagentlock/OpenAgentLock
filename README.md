<div align="center">

<img src="assets/logo-mark.svg" alt="OpenAgentLock" width="128" height="128" />

# OpenAgentLock

**A locally-hosted, open-source firewall for AI coding agents.**

[![CI](https://img.shields.io/github/actions/workflow/status/openagentlock/openagentlock/ci.yml?branch=main&label=ci&style=flat-square)](https://github.com/openagentlock/openagentlock/actions/workflows/ci.yml)
[![docker-publish](https://img.shields.io/github/actions/workflow/status/openagentlock/openagentlock/docker-publish.yml?branch=main&label=docker&style=flat-square)](https://github.com/openagentlock/openagentlock/actions/workflows/docker-publish.yml)
[![npm](https://img.shields.io/npm/v/%40openagentlock%2Fcli?style=flat-square&label=%40openagentlock%2Fcli)](https://www.npmjs.com/package/@openagentlock/cli)
[![ghcr](https://img.shields.io/badge/ghcr.io-control--plane-black?style=flat-square&logo=docker&logoColor=white)](https://github.com/openagentlock/openagentlock/pkgs/container/control-plane)
[![license](https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-black?style=flat-square)](LICENSE)
[![docs](https://img.shields.io/badge/docs-openagentlock.dev-black?style=flat-square)](https://openagentlock.dev/)
[![stars](https://img.shields.io/github/stars/openagentlock/openagentlock?style=flat-square)](https://github.com/openagentlock/openagentlock/stargazers)

[Documentation](https://openagentlock.dev/) · [Getting started](https://openagentlock.dev/guide/getting-started/) · [Status](https://openagentlock.dev/status/) · [Architecture](https://openagentlock.dev/architecture/overview/)

</div>

---

OpenAgentLock detects local AI coding agent harnesses (Claude Code, Codex CLI, Cursor, OpenCode, Cline, Gemini CLI, Continue.dev, VS Code Copilot), gates risky tool calls with a deterministic YAML policy, and anchors every decision in a tamper-evident Merkle ledger. Install once and keep working in your harness as normal — your workflow does not change.

## Quick start

```bash
# 1. Pull and start the control plane
curl -O https://raw.githubusercontent.com/openagentlock/openagentlock/main/docker-compose.yml
docker compose up -d

# 2. Install the CLI
brew install openagentlock/tap/agentlock
# or: bun add -g @openagentlock/cli
# or: npm i -g @openagentlock/cli

# 3. Wire it up
agentlock detect
agentlock install
```

Then open the local web dashboard at <http://127.0.0.1:7879/>.

Full walkthrough at <https://openagentlock.dev/guide/getting-started/>.

## What ships today

| Surface | Status |
|---|---|
| `agentlock detect` | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| `agentlock install` (Claude Code, Codex CLI) | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| `agentlock install` (Cursor, OpenCode, Cline, Gemini CLI, Continue, VS Code Copilot) | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |
| Five baseline gates in monitor mode | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Tamper-evident Merkle ledger | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Local web dashboard | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Software + TOTP signers | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| OS keychain signer, hardware-key (YubiKey) signer | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |
| OIDC SSO + RBAC + LDAP | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |
| Signed PDF audit report | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |

The complete shipped/not-yet matrix lives at <https://openagentlock.dev/status/>.

## How it works

```
┌─────────────────┐    hook    ┌──────────────────┐    FFI    ┌────────────┐
│  Agent harness  │  ─────────▶│   Control plane  │ ────────▶ │   Ledger   │
│  (Claude Code,  │            │  (Go, Docker,    │           │  (Rust,    │
│   Codex, …)     │◀─ verdict ─│   :7878)         │           │   Merkle)  │
└─────────────────┘            └──────────────────┘           └────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │   Local web      │
                              │   dashboard      │
                              │   (:7879)        │
                              └──────────────────┘
```

Three languages, one repo:

- **`cli/`** — TypeScript on Bun, runs on your host. Owns the long-lived signing key.
- **`control-plane/`** — Go HTTP service in Docker. Evaluates policy, drives install plan/apply, appends to ledger.
- **`ledger/`** — Rust crate. Merkle log + verification, exposed to Go via FFI so verification logic exists in exactly one place.

See [Architecture overview](https://openagentlock.dev/architecture/overview/) for the why behind the split.

## The five gates

Every install ships [`policies/default.yaml`](policies/default.yaml) with five gates in monitor mode:

| Gate | What it catches |
|---|---|
| `supply-chain.pkg-install` | `pip install`, `npm install`, `brew install`, `cargo install` |
| `supply-chain.untrusted-mcp` | MCP server with an unpinned public key |
| `rogue.secret-read` | reads of `.env`, `~/.ssh`, `~/.aws/credentials`, anywhere a secret-shaped path appears |
| `rogue.net-egress` | `curl`, `wget`, MCP HTTP tools |
| `rogue.destructive-bash` | `rm -rf`, `git push --force`, `DROP TABLE`, `kubectl delete` |

See [Policies and the five gates](https://openagentlock.dev/guide/policies/) for the rule schema and authoring rules.

## Repository layout

```
cli/                        TypeScript + Bun + OpenTUI                — @openagentlock/cli
control-plane/              Go HTTP service in Docker                 — ghcr.io/openagentlock/control-plane
  api/openapi.yaml          source-of-truth API contract
  Dockerfile, docker-compose.yml
  dashboard-ui/             Vite SPA embedded into the Go binary
ledger/                     Rust crate (lib + cdylib + staticlib)     — openagentlock-ledger
policies/default.yaml       baseline policy shipped with every install
docs/                       MkDocs Material site (deployed to openagentlock.dev)
assets/                     logo, favicon, social card
Formula/agentlock.rb        Homebrew tap formula
docker-compose.yml          one-command control-plane bring-up
scripts/install.sh          one-shot installer
.github/workflows/          ci · docker-publish · npm-publish · pages
```

## Status

Pre-1.0. Targets [DEFCON 34 Demo Labs](https://defcon.org/) (August 2026).

We try not to break anything that already works. Surfaces marked "shipped" have tests; surfaces marked "not yet" exist as scaffolding or stubs and are explicitly disabled in the user-facing path.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup and the workflow.

By contributing you agree your contributions are licensed under the FSL-1.1-Apache-2.0 found in [`LICENSE`](LICENSE).

We follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). For security disclosures see [`SECURITY.md`](SECURITY.md).

## License

[Functional Source License 1.1, Apache 2.0 Future License](LICENSE) (`FSL-1.1-Apache-2.0`).

Permits any non-competitive use today; auto-converts to Apache 2.0 two years after each release.
