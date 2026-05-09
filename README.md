<div align="center">

<img src="assets/banner.svg" alt="OpenAgentLock — A firewall for AI coding agents" width="100%" />

**A locally-hosted, open-source firewall for AI coding agents.**

[![CI](https://img.shields.io/github/actions/workflow/status/openagentlock/openagentlock/ci.yml?branch=main&label=ci&style=flat-square)](https://github.com/openagentlock/OpenAgentLock/actions/workflows/ci.yml)
[![docker-publish](https://img.shields.io/github/actions/workflow/status/openagentlock/openagentlock/docker-publish.yml?branch=main&label=docker&style=flat-square)](https://github.com/openagentlock/OpenAgentLock/actions/workflows/docker-publish.yml)
[![npm](https://img.shields.io/npm/v/%40openagentlock%2Fcli?style=flat-square&label=%40openagentlock%2Fcli)](https://www.npmjs.com/package/@openagentlock/cli)
[![ghcr](https://img.shields.io/badge/ghcr.io-agentlockd-black?style=flat-square&logo=docker&logoColor=white)](https://github.com/openagentlock/OpenAgentLock/pkgs/container/agentlockd)
[![license](https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-black?style=flat-square)](LICENSE)
[![docs](https://img.shields.io/badge/docs-openagentlock.github.io/OpenAgentLock-black?style=flat-square)](https://openagentlock.github.io/OpenAgentLock/)
[![stars](https://img.shields.io/github/stars/openagentlock/openagentlock?style=flat-square)](https://github.com/openagentlock/OpenAgentLock/stargazers)

[Documentation](https://openagentlock.github.io/OpenAgentLock/) · [Getting started](https://openagentlock.github.io/OpenAgentLock/guide/getting-started/) · [Rules registry](https://openagentlock.github.io/rules/) · [Status](https://openagentlock.github.io/OpenAgentLock/status/) · [Architecture](https://openagentlock.github.io/OpenAgentLock/architecture/overview/)

</div>

---

OpenAgentLock detects local AI coding agent harnesses (Claude Code, Codex CLI, Cursor, OpenCode, Cline, Gemini CLI, Continue.dev, VS Code Copilot), gates risky tool calls with a deterministic YAML policy, and anchors every decision in a tamper-evident Merkle ledger. Install once and keep working in your harness as normal — your workflow does not change.

## Quick start

```bash
# 1. Pull and start the daemon
docker pull ghcr.io/openagentlock/agentlockd:latest
docker run -d --name agentlock \
  -p 127.0.0.1:7878:7878 \
  -p 127.0.0.1:7879:7879 \
  -v agentlock-state:/var/lib/agentlock \
  -e NVIDIA_API_KEY \
  -e OPENROUTER_API_KEY \
  ghcr.io/openagentlock/agentlockd:latest

# 2. Install the CLI
npm i -g @openagentlock/cli
# or: bun add -g @openagentlock/cli

# 3. Enroll a signer (TOTP — recommended for prod)
agentlock signer enroll --tier totp --passphrase 'your-passphrase-here'
# scan the otpauth:// QR with Google Authenticator / 1Password / Authy.

# 4. Wire your harnesses with a TOTP-attested session
agentlock detect
agentlock install --tier totp --code 123456 --passphrase 'your-passphrase-here'
```

For a quick eval without a signer (dev only): start the daemon with `-e AGENTLOCK_ALLOW_UNATTESTED=1`, then `agentlock install` (defaults to unattested).

Optional external guardrails are enabled by starting the daemon with `NVIDIA_API_KEY` and/or `OPENROUTER_API_KEY`; keys are held in control-plane memory only. In the current shipped slice, NVIDIA provides post-local-allow runtime classification, while OpenRouter is catalog visibility only.

Open the local web dashboard at <http://127.0.0.1:7879/>, or run `agentlock dashboard` for a terminal TUI with the same live ledger tail, sessions, loaded gates, and a one-key monitor⇄enforce flip.

<div align="center">
  <img src="assets/tui/dashboard-stats.png" alt="agentlock dashboard — Stats tab with live activity sparkline, top deny rules, and per-source counts" width="100%" />
  <sub><i><code>agentlock dashboard</code> — live ledger tail, top deny rules/tools, per-source counts, one-key firewall ↔ monitor flip.</i></sub>
</div>

Full walkthrough at <https://openagentlock.github.io/OpenAgentLock/guide/getting-started/>.

## Community rules registry

Need more gates than the thirteen that ship in the baseline? Browse the community catalog at <https://openagentlock.github.io/rules/> — network exfil host allowlists, package typosquat, broader persistence shapes, plus org-specific rules. Install with one command:

```bash
agentlock rules sync
agentlock rules search exfil
agentlock rules install rogue.secret-read
```

Or run your own private registry — any Git repo with the same layout works. Source: [openagentlock/rules](https://github.com/openagentlock/rules).

For agents that need to **author** new rules from natural-language intent, see [openagentlock/skills](https://github.com/openagentlock/skills) — Claude Code / Cursor / Codex skills that drive the `agentlock rules` CLI.

## What ships today

| Surface | Status |
|---|---|
| `agentlock detect` | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| `agentlock install` (Claude Code, Codex CLI, Cursor, Gemini CLI) | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| `agentlock install --tier {unattested,software,totp}` | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| `agentlock doctor` | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| `agentlock install` (OpenCode, Cline, Continue, VS Code Copilot) | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |
| Thirteen cross-harness baseline gates in enforce mode (no `rules install` needed) | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Tamper-evident Merkle ledger | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Local web dashboard | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Software + TOTP signers (with `signer enroll` + session mint) | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| OS keychain signer (macOS) | ![shipped](https://img.shields.io/badge/-shipped-16a34a?style=flat-square) |
| Hardware-key signer (YubiKey PIV / FIDO2) | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |
| OIDC SSO + RBAC + LDAP | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |
| Signed PDF audit report | ![not yet](https://img.shields.io/badge/-not%20yet-f59e0b?style=flat-square) |

The complete shipped/not-yet matrix lives at <https://openagentlock.github.io/OpenAgentLock/status/>.

## How it works

```mermaid
flowchart LR
    subgraph host["Your host"]
      H["Agent harness<br/><i>Claude Code · Codex CLI · Cursor · Gemini CLI</i>"]
      CLI["agentlock CLI<br/><i>owns long-lived signing key</i>"]
    end
    subgraph docker["Docker (127.0.0.1)"]
      CP[":7878 control plane<br/><i>policy · install · ledger appender</i>"]
      DB[":7879 web dashboard"]
      L[("Merkle ledger<br/>Rust crate via FFI")]
    end
    H -->|"pre-tool hook"| CP
    CP -->|"verdict<br/>allow / deny"| H
    CLI -->|"signed session"| CP
    CP --> L
    CP --- DB
```

Three languages, one repo:

- **`cli/`** — TypeScript on Bun, runs on your host. Owns the long-lived signing key.
- **`control-plane/`** — Go HTTP service in Docker. Evaluates policy, drives install plan/apply, appends to ledger.
- **`ledger/`** — Rust crate. Merkle log + verification, exposed to Go via FFI so verification logic exists in exactly one place.

See [Architecture overview](https://openagentlock.github.io/OpenAgentLock/architecture/overview/) for the why behind the split.

## Policy — baseline + registry

OpenAgentLock ships a **thirteen-gate enforce-mode baseline** embedded in the daemon binary (source: [`control-plane/internal/policy/baseline.yaml`](./control-plane/internal/policy/baseline.yaml)). Fresh installs block destructive shell commands, supply-chain RCE shapes (`curl … | bash`, `eval $(curl …)`), reverse shells, secret/credential reads (`.env`, `.aws/credentials`, gcloud/Azure/Terraform state), defence evasion (`iptables -F`, `csrutil disable`, `history -c`), `chmod 777`, destructive `kubectl delete ns` / `helm uninstall`, force-push to shared branches, writes to `/etc/sudoers` / `~/.ssh/authorized_keys`, persistence appends to `~/.bashrc` / `~/.zshrc`, and cron/systemd-timer install — across **Claude Code, Codex, Cursor, Claude Desktop, and Gemini (via MCP)** without an `agentlock rules install` step. Each gate uses `any_of` arms covering `Bash` + `Shell` + `tool_prefix: mcp_` (catches both Claude/Cursor's `mcp__` double-underscore and Gemini's `mcp_` single-underscore wire shape) and, for write/edit gates, `Write` + `Edit` + `MultiEdit`. See [`docs/guide/policies.md`](./docs/guide/policies.md#first-boot-baseline-policy) for the full gate inventory and per-harness coverage matrix.

Layer org-specific or broader coverage on top via the [openagentlock/rules](https://github.com/openagentlock/rules) registry:

```bash
agentlock rules sync                                 # tap the upstream registry
agentlock rules search exfil                         # browse by keyword
agentlock rules install rogue.net-egress             # block unknown-host curl/wget
agentlock rules install supply-chain.npm-untrusted   # deny installs from URL/git/tarball
agentlock rules install exfil.curl-with-env          # catch $ENV_VAR exfil shapes
```

You can also tap a private registry (any Git repo with the same layout) for org-internal rules:

```bash
agentlock rules add https://github.com/your-org/your-rules.git
```

See [Policies and rules](https://openagentlock.github.io/OpenAgentLock/guide/policies/) for the schema and authoring guide.

## Repository layout

```
cli/                        TypeScript + Bun + OpenTUI                — @openagentlock/cli
control-plane/              Go HTTP service in Docker                 — ghcr.io/openagentlock/agentlockd
  api/openapi.yaml          source-of-truth API contract
  Dockerfile, docker-compose.yml
  dashboard-ui/             Vite SPA embedded into the Go binary
ledger/                     Rust crate (lib + cdylib + staticlib)     — openagentlock-ledger
docs/                       MkDocs Material site (deployed to openagentlock.github.io/OpenAgentLock)
assets/                     logo, favicon, social card
docker-compose.yml          one-command control-plane bring-up
scripts/install.sh          one-shot installer
.github/workflows/          ci · docker-publish · npm-publish · pages
```

## Status

Pre-1.0.

We try not to break anything that already works. Surfaces marked "shipped" have tests; surfaces marked "not yet" exist as scaffolding or stubs and are explicitly disabled in the user-facing path.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup and the workflow.

By contributing you agree your contributions are licensed under the FSL-1.1-Apache-2.0 found in [`LICENSE`](LICENSE).

We follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). For security disclosures see [`SECURITY.md`](SECURITY.md).

## License

[Functional Source License 1.1, Apache 2.0 Future License](LICENSE) (`FSL-1.1-Apache-2.0`).

Permits any non-competitive use today; auto-converts to Apache 2.0 two years after each release.
