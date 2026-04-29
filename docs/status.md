# Status

Live status of every component shipped to the public repo. <span class="md-status-pill shipped">Shipped</span> means it is in `main` and has tests; <span class="md-status-pill not-yet">Not yet implemented</span> means the surface exists but is intentionally disabled or stubbed pending sign-off.

## CLI

| Surface | Status |
|---|---|
| `agentlock detect` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock install` (Claude Code, Codex CLI) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock install` (Cursor, OpenCode, Cline, Gemini CLI, Continue, VS Code Copilot) | <span class="md-status-pill not-yet">Not yet implemented</span> — detected but disabled in selector |
| `agentlock status` | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock signer enroll` (TOTP) | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock signer enroll` (OS keychain) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| `agentlock signer enroll` (hardware key — YubiKey) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| `agentlock hook codex <event>` shim | <span class="md-status-pill shipped">Shipped</span> |
| `agentlock login` | <span class="md-status-pill shipped">Shipped</span> (password mode only) |

## Control plane

| Endpoint group | Status |
|---|---|
| `/v1/health` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/gates`, `/v1/mode` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/install/plan`, `/v1/install/apply`, `/v1/uninstall` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/mcp/pin/check`, `/v1/mcp/pin/accept` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/sessions/*`, `/v1/sessions/insights` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/ledger/root`, `/v1/ledger/proof/:seq`, `/v1/ledger/verify` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/claude-code/*` | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/hooks/codex/*` | <span class="md-status-pill shipped">Shipped</span> |
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
| `ghcr.io/openagentlock/control-plane` Docker image | <span class="md-status-pill shipped">Shipped</span> on tag |
| `@openagentlock/cli` on npm | <span class="md-status-pill shipped">Shipped</span> on tag |
| `openagentlock/tap/agentlock` Homebrew formula | <span class="md-status-pill shipped">Shipped</span> on tag |
| `pip install openagentlock` | <span class="md-status-pill not-yet">Not yet implemented</span> — Bun-native CLI; pip wrapper is roadmap if demand surfaces |

## Other surfaces

| Surface | Status |
|---|---|
| MCP observation via lifecycle hooks (Claude Code, Cursor, Cline, Gemini CLI, OpenCode) | <span class="md-status-pill shipped">Shipped</span> on the hook side; OpenCode does not currently fire the pre-tool hook for MCP |
| MCP fingerprint pinning (`/v1/mcp/pin`) | <span class="md-status-pill shipped">Shipped</span> |
| OIDC SSO + RBAC + LDAP | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Group / scoped policy with inheritance | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Federated deployment (per-dev daemons + central control plane) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Signed PDF audit report | <span class="md-status-pill not-yet">Not yet implemented</span> |
