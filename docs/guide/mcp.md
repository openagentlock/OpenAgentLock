# MCP

OpenAgentLock observes Model Context Protocol (MCP) servers through the **harness's own lifecycle hooks**. We do not run a stdio MITM in front of MCP servers; that approach was explored and rejected because it changes the trust shape of the system without adding meaningful guarantees.

## How it works

When a harness calls a tool exposed by an MCP server, the harness fires its pre-tool hook before execution. That hook lands at the control plane (`/v1/hooks/<harness>/pre-tool`) with the call's tool name, arguments, and (where the harness exposes it) the MCP server's identity.

The control plane:

1. Looks up the MCP server's fingerprint in its pin store
2. If unpinned, queues a pin request (visible in the dashboard)
3. Evaluates policy as for any other tool call
4. Returns `allow` or `deny`

Decisions land in the ledger with `source: <harness>` and the MCP server's pinned key id.

## MCP coverage by harness

| Harness | Pre-tool hook fires for MCP? | Notes |
|---|---|---|
| Claude Code | yes | full coverage via HTTP hooks |
| Cursor | yes | shipped on the hook side |
| Cline | yes | shipped on the hook side |
| Gemini CLI | yes | shipped on the hook side |
| Continue.dev | yes | shipped on the hook side |
| OpenCode | **no** | the `tool.execute.before` hook does **not** currently fire for MCP — see [sst/opencode#2319](https://github.com/sst/opencode/issues/2319) |
| Codex CLI | not yet | hook surface exists but command hooks are bash-only today; MCP hook is a tracked upstream gap |
| Aider, Copilot CLI | no | no hook surface at all |

The dashboard shows MCP coverage per session so you know whether a given run had MCP visibility.

## Pinning

The first time a new MCP server is observed, we record its self-reported public key fingerprint and queue a pin request. Until you accept the pin from the dashboard, calls to that server count as "untrusted MCP" and trigger the `supply-chain.untrusted-mcp` gate.

The pin store lives at `${AGENTLOCK_HOME}/mcp-pins.json`. Edit it manually only if you know what you're doing.

## What we do **not** do

- We do **not** run an MCP proxy. The control plane never speaks the MCP wire protocol.
- We do **not** rewrite harness MCP configs. Pinning is observational, not enforcing.
- We do **not** sandbox MCP server processes. That is the OS's job.
