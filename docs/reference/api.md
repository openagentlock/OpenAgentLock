# HTTP API

The control plane exposes a versioned HTTP API on `127.0.0.1:7878`. The contract source is [`api/openapi.yaml`](https://github.com/openagentlock/OpenAgentLock/blob/main/control-plane/api/openapi.yaml). What follows is a quick reference; refer to the OpenAPI for full schemas.

## Health

`GET /v1/health`

```json
{ "status": "ok", "version": "0.1.0" }
```

## Mode

`GET /v1/mode` · `PATCH /v1/mode`

Toggles the daemon-level `monitor` ↔ `firewall` switch. This is the outer override and beats the policy file's own `mode` in both directions: `firewall` re-escalates any policy-monitor match back to `deny`; `monitor` suppresses every `deny`. See [Policies](../guide/policies.md#two-switches-mode-and-rule-actions).

## Gates

`GET /v1/gates`

Returns the list of currently active gates with their per-gate status (matched count, last-hit timestamp).

`POST /v1/gates/check`

Synchronous verdict for a single tool call. Request body:

- `session_id` — required, string. From `POST /v1/sessions/create`.
- `source` — required, string. Harness id (`claude-code`, `codex`, `cursor`, `mcp-proxy`).
- `tool` — required, string. The tool name being checked (`Bash`, `Read`, `Write`, `mcp__<server>__<method>`).
- `input` — required, object. The tool's input shape (e.g. `{ "command": "rm -rf foo" }` for Bash).
- `cwd` — optional, string. Working directory if relevant to the rule.
- `meta` — optional, object. Free-form context for evaluators that look beyond `input`.

Response fields:

- `verdict` — `allow` or `deny` (the daemon never returns `ask` on this path)
- `rule_id` — id of the gate that matched, empty when no rule fired
- `reason` — short human-readable explanation, surfaced verbatim by the harness shim
- `nudge` — optional, string. Present only when the matched rule defined a `nudge:` hint **and** the final verdict is `deny`. Allow / monitor-suppressed paths drop it. See [Policies → Nudges](../guide/policies.md#nudges).
- `ledger_seq` — sequence number of the corresponding ledger leaf

## Install

`POST /v1/install/plan` — render a diff of what would change in the harness configs

`POST /v1/install/apply` — apply a previously-planned diff (with idempotency token)

`POST /v1/uninstall` — remove all hook entries this control plane has previously written

## MCP pinning

`POST /v1/mcp/pin/check` · `POST /v1/mcp/pin/accept`

The first time a new MCP server fingerprint is seen, it's queued for pinning. Accept the pin from the dashboard or via this endpoint.

## Sessions

`POST /v1/sessions/create` — bootstrap a new short-lived session, signed by the host CLI's long-lived key

`GET /v1/sessions/:id` — session metadata

`POST /v1/sessions/heartbeat` — keep a session alive

`GET /v1/sessions/insights` — aggregate per-session activity counts (used by the dashboard)

## Ledger

`GET /v1/ledger/root` — current Merkle root, sequence, signer kind

`GET /v1/ledger/proof/:seq` — inclusion proof for the leaf at `seq`

`POST /v1/ledger/verify` — offline verify a `(leaf, seq, proof, root)` tuple

## Hooks (harness-facing)

`POST /v1/hooks/claude-code/<event>`

`POST /v1/hooks/codex/<event>`

`POST /v1/hooks/<harness>/<event>` (other harnesses; not yet implemented in the installer)

The hook event names mirror the harness's own naming. See [Hooks](hooks.md).

## Authentication

`GET /v1/auth/mode` — returns the active auth mode (`password`, `oidc`, or `ldap`)

`POST /v1/auth/login` — password-mode login (the only currently-shipped mode)

OIDC and LDAP modes are stubbed; calling them returns a hint string explaining what is missing. See [Authentication](../guide/auth.md).
