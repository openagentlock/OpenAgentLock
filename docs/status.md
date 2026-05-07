# Status

Live status of every component shipped to the public repo. <span class="md-status-pill shipped">Shipped</span> means it is in `main` and has tests; <span class="md-status-pill not-yet">Not yet implemented</span> means the surface exists but is intentionally disabled or stubbed pending sign-off.

## CLI

| Surface | Status |
|---|---|
| `agentlock detect` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock install` (Claude Code, Codex CLI, Cursor, Gemini CLI) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock install` (Claude Desktop) | <span class="md-status-pill shipped">Shipped</span> — **MCP-slice enforcement** via `agentlock mcp-proxy`. Wraps every user-installed MCP server and `.mcpb` Desktop Extension; each `tools/call` goes through daemon policy. **Not gated:** Computer Use (direct mouse/keyboard), integrated terminal, native connectors (Slack/GCal), and server-side features (web search, code interpreter). **Cowork coverage uncertain:** any MCP-mediated tool call Cowork makes IS gated; whether Cowork has separate non-MCP code paths is unverified — verify in your environment by running a Cowork task and checking the agentlock ledger. For full local enforcement of an agent harness, use Claude Code. Tracks [anthropics/claude-code#45514](https://github.com/anthropics/claude-code/issues/45514) for native PreToolUse parity. |
| `agentlock install` (OpenCode, Cline, Continue, VS Code Copilot) | <span class="md-status-pill not-yet">Not yet implemented</span> — detected but disabled in selector |
| `agentlock install` (Codex Desktop, Openclaw, Nemoclaw, Hermesagent, Pi) | <span class="md-status-pill not-yet">Not yet implemented</span> — roadmap; awaiting per-app hook/config investigation |
| `agentlock install --tier {unattested,software,totp}` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock status` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock signer enroll --tier totp` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock signer enroll --tier os-keychain` (macOS, optional `--ttl`) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock signer enroll --tier yubikey` (PIV / FIDO2) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| `agentlock session create / rotate / end` (software, totp) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock hook claude-code / codex / cursor / gemini <event>` shims | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock mcp-server` (Claude Desktop MCP stdio server, read-only) | <span class="md-status-pill shipped">Shipped</span> — exposes status + ledger query tools |
| `agentlock mcp-proxy` (Claude Desktop tools/call gate) | <span class="md-status-pill shipped">Shipped</span> — sits between Desktop and each user MCP server, fail-open on daemon-down |
| `agentlock ledger root / verify` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock fake-hook` (eval / scenario harness) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock dashboard` (open local web dashboard) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock login` | <span class="md-status-pill shipped">Shipped</span> (password mode only) |
| `agentlock rules add / sources / sync / search / install / uninstall / remove` | <span class="md-status-pill shipped">Shipped</span> — backed by [openagentlock/rules](https://github.com/openagentlock/rules) |

## Control plane

| Endpoint group | Status |
|---|---|
| `/v1/health` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/gates`, `/v1/mode` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/policy/view`, `/v1/policy/gates` (POST/PATCH/DELETE), `/v1/policy/gates/yaml` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/install/plan`, `/v1/install/apply`, `/v1/uninstall` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/mcp/pin/check`, `/v1/mcp/pin/accept` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/sessions/*`, `/v1/sessions/insights` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/ledger/root`, `/v1/ledger/proof/:seq`, `/v1/ledger/verify` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/claude-code/*` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/codex/*` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/cursor/*` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/gemini/*` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/claude-desktop/*` | <span class="md-status-pill shipped">Shipped</span> — called by `agentlock mcp-proxy`, not by Claude Desktop directly |
| `/v1/auth` (password) | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/auth` (OIDC) | <span class="md-status-pill not-yet">Not yet implemented</span> — stub returns mode hint |
| `/v1/auth` (LDAP) | <span class="md-status-pill not-yet">Not yet implemented</span> — stub returns mode hint |
| Signed-PDF report endpoint | <span class="md-status-pill not-yet">Not yet implemented</span> — `501 Not Implemented` |
| Local web dashboard at `127.0.0.1:7879` | <span class="md-status-pill shipped">Shipped</span> |

## Ledger

| Function | Status |
|---|---|
| `leaf_hash` | <span class="md-status-pill shipped">Shipped</span> |
| `merkle_root` (RFC 6962 odd-tail) | <span class="md-status-pill shipped">Shipped</span> |
| `inclusion_proof` | <span class="md-status-pill shipped">Shipped</span> |
| `verify_proof` | <span class="md-status-pill shipped">Shipped</span> |
| FFI staticlib for Go | <span class="md-status-pill shipped">Shipped</span> |
| Ten regression tests in `tests/merkle.rs` | <span class="md-status-pill shipped">Shipped</span> all green |

## Policy

| Gate | Default verdict |
|---|---|
| `supply-chain.pkg-install` | monitor |
| `supply-chain.untrusted-mcp` | monitor |
| `rogue.secret-read` | monitor |
| `rogue.net-egress` | monitor |
| `rogue.destructive-bash` | monitor |

Flip to `mode: enforce` at the top of your policy file when you've reviewed activity and are ready to start blocking.

## Distribution

| Channel | Status |
|---|---|
| `ghcr.io/openagentlock/agentlockd` Docker image | <span class="md-status-pill shipped">Shipped</span> on tag |
| `@openagentlock/cli` on npm | <span class="md-status-pill shipped">Shipped</span> on tag |
| `pip install openagentlock` | <span class="md-status-pill not-yet">Not yet implemented</span> — Bun-native CLI; pip wrapper is roadmap if demand surfaces |

## Other surfaces

| Surface | Status |
|---|---|
| MCP observation via lifecycle hooks (Claude Code, Cursor, Cline, Gemini CLI, OpenCode) | <span class="md-status-pill shipped">Shipped</span> on the hook side; OpenCode does not currently fire the pre-tool hook for MCP |
| MCP fingerprint pinning (`/v1/mcp/pin`) | <span class="md-status-pill shipped">Shipped</span> |
| OIDC SSO + RBAC + LDAP | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Group / scoped policy with inheritance | <span class="md-status-pill shipped">Shipped</span> — filesystem-backed `group-policy.yaml`, deny-overrides, explicit priority conflict handling; OIDC group source remains under auth epic |
| Federated deployment (per-dev daemons + central control plane) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Signed PDF audit report | <span class="md-status-pill not-yet">Not yet implemented</span> |
