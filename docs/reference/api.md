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
- `source` — required, string. Harness id (`claude-code`, `codex`, `cursor`, `gemini`, `mcp-proxy`, or another detected source).
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

The corresponding ledger entry may include `policy_trace`, listing every daemon / registry / group / user / repo layer that contributed a verdict.

`GET /v1/policy/view`

Returns the live policy as dashboard-friendly gates. Each gate includes `source`: `daemon` for built-in or direct policy-file gates, `registry:<id>` for rules installed from a rules registry, or `per-repo:<path>` for repo-local gates.

## False Positives

`GET /v1/false-positives/cases/:seq`

Builds a redacted case bundle from a matched ledger event. The event must have a matched rule and must be a deny or monitor alert. Add `?include_raw=true` only when the caller explicitly wants raw event input included.

`POST /v1/false-positives/validate`

Validates replacement gate YAML against a case bundle. The replacement must parse as a gate and must not deny the original false-positive event.

`POST /v1/false-positives/apply`

Atomically marks the old matched gate `disabled: true` and appends the replacement gate. The request includes the case bundle policy hash; stale bundles are rejected so a dashboard cannot overwrite newer policy edits.

## Install

`POST /v1/install/plan` — render a diff of what would change in the harness configs

`POST /v1/install/apply` — apply a previously-planned diff (with idempotency token)

`POST /v1/uninstall` — remove all hook entries this control plane has previously written

## MCP pinning

`POST /v1/mcp/pin/check` · `POST /v1/mcp/pin/accept`

The first time a new MCP server fingerprint is seen, it's queued for pinning. Accept the pin from the dashboard or via this endpoint.

## Sessions

`POST /v1/sessions/create` — bootstrap a new short-lived session, signed by the host CLI's long-lived key

Session create/rotate accepts optional `user_id` and `groups` fields. These are used by `AGENTLOCK_HOME/group-policy.yaml` until OIDC/LDAP group-claim resolution lands.

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

`POST /v1/hooks/cursor/<event>`

`POST /v1/hooks/gemini/<event>`

`POST /v1/hooks/<harness>/<event>` (other harnesses; not yet implemented in the installer)

The hook event names mirror the harness's own naming. See [Hooks](hooks.md).

## Authentication

`GET /v1/auth/mode` — returns the active auth mode (`password`, `oidc`, or `ldap`)

`POST /v1/auth/login` — password-mode login (the only currently-shipped mode)

OIDC and LDAP modes are stubbed; calling them returns a hint string explaining what is missing. See [Authentication](../guide/auth.md).
