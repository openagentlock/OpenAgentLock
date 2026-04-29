# HTTP API

The control plane exposes a versioned HTTP API on `127.0.0.1:7878`. The contract source is [`api/openapi.yaml`](https://github.com/openagentlock/openagentlock/blob/main/control-plane/api/openapi.yaml). What follows is a quick reference; refer to the OpenAPI for full schemas.

## Health

`GET /v1/health`

```json
{ "status": "ok", "version": "0.1.0" }
```

## Mode

`GET /v1/mode` · `PATCH /v1/mode`

Toggles the daemon-level `monitor` ↔ `enforce` switch. Independent from the policy file's own `mode` field — see [Policies](../guide/policies.md#two-switches-mode-and-rule-actions).

## Gates

`GET /v1/gates`

Returns the list of currently active gates with their per-gate status (matched count, last-hit timestamp).

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
