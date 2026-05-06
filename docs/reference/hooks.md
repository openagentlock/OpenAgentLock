# Hooks

Each agent harness exposes a different shape of hook. OpenAgentLock targets each on its native terms.

## Claude Code

Claude Code uses **command hooks**. The installer adds entries to `~/.claude/settings.json` that spawn the `agentlock hook claude-code <event>` shim:

```json
{
  "hooks": {
    "PreToolUse": [{
      "_agentlock": true,
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "agentlock hook claude-code pre-tool-use",
        "env": { "AGENTLOCK_DAEMON_URL": "http://127.0.0.1:7878" },
        "timeout": 60
      }]
    }]
  }
}
```

The shim POSTs to `/v1/hooks/claude-code/<event>` and translates the response into Claude's exit-code / JSON contract. Routing through a shim — instead of Claude's native HTTP hooks — lets the harness fail-open silently on a daemon outage instead of surfacing a red "PreToolUse hook error / ECONNREFUSED" banner on every tool call.

### Daemon-down UX

When the daemon is unreachable, the shim never writes user-visible text into stdout — anything that reaches Claude's `additionalContext` / Cursor's `agent_message` lands in the model's input stream and registers as a prompt-injection attempt, regardless of wording. We surface daemon health through channels that bypass the model entirely, with a different surface per harness based on what each one's hook spec actually exposes:

- **Claude Code — live `statusLine`** (best UX). The installer writes a `statusLine` entry in `~/.claude/settings.json` pointing at a tiny health-check script at `<agentlockHome>/bin/agentlock-status`. Claude Code re-runs that script on every UI render and shows the result as a persistent element under the chat: `OpenAgentLock ✓` when the daemon is up, `OpenAgentLock ⚠ daemon offline` when it's not. The output is pure UI — never seen by the model.
- **Codex CLI — silent fail-open**. Codex has no `statusLine` analog and hides hook stderr on exit-0 (it only surfaces hook output as a red `(failed)` banner when the hook exits non-zero, which is the wrong channel for a status nudge). There is no in-Codex UI surface available for an indicator that won't either look like an error or pollute the model's input. The shim stays silent on every event when the daemon is unreachable.
- **Cursor — silent fail-open**. Cursor's hook spec has no UI surface that's outside the model's input stream and no statusLine equivalent. On daemon failures the shim emits a plain `{"permission":"allow"}` envelope and stays silent. A live indicator for Cursor would need a real Cursor extension; tracked separately.
- **Gemini CLI — silent fail-open**. Gemini hooks have no status-line equivalent. On daemon failures the shim stays silent and lets the tool call continue.

All four harnesses share the wrapper-stability fix: the hook command that Claude Code / Codex / Cursor / Gemini spawn points at `<agentlockHome>/bin/agentlock` (e.g. `~/Library/Application Support/OpenAgentLock/bin/agentlock` on macOS), written by `agentlock install`. The path lives in our state dir, not in the package manager's `node_modules` tree, so package upgrades don't strand the wired path. The same applies to `agentlock-status`. Both paths are shell-quoted in the wired command string so spaces (`Application Support`) survive `/bin/sh -c` parsing.

## Codex CLI

Codex uses **command hooks** declared in `~/.codex/config.toml`. The CLI ships an `agentlock hook codex <event>` shim so the same control-plane endpoints are reused:

```toml
codex_hooks = true

[[hook]]
event = "pre_tool"
command = ["agentlock", "hook", "codex", "pre-tool"]
```

`agentlock install` auto-enables the flag for you: it creates `~/.codex/config.toml` if missing, flips `codex_hooks = false` to `true`, or appends the line to an existing TOML — backing the original up first. The flag stays user-removable; we never enable it without an install run.

Codex command hooks are bash-only today; MCP coverage at the hook layer is a tracked upstream gap, not something we can paper over.

Daemon-down behavior is documented in the **Daemon-down UX** section above — Codex stays silent (it has no UI surface that renders on exit-0 hooks).

## Cursor

Cursor (≥1.7) uses **command hooks** in `~/.cursor/hooks.json`. The installer wires the `agentlock hook cursor <event>` shim for `sessionStart`, `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `postToolUse`, and `sessionEnd`. The shim emits Cursor's `{permission, agent_message?}` shape on stdout.

Daemon-down behavior is documented in the **Daemon-down UX** section above — Cursor gets silent fail-open on transport errors. We never set `agent_message` on those, since that field lands in the model's input stream and would register as a prompt-injection attempt.

## Gemini CLI

Gemini CLI uses command hooks in `~/.gemini/settings.json`. The installer wires the `agentlock hook gemini <event>` shim for the same lifecycle shape as the Gemini settings file exposes, including pre-tool and post-tool events. The shim emits Gemini's permission-decision response shape on stdout.

Daemon-down behavior is documented in the **Daemon-down UX** section above — Gemini gets silent fail-open on transport errors.

## Other harnesses

OpenCode, Cline, and Continue.dev expose a hook surface but **the installer does not yet write to them**. The detectors find the harness, the picker shows it, and the install plan flags it as not yet implemented. Wiring is a follow-up tracked in the public roadmap.

VS Code Copilot has no general-purpose pre-tool hook surface; we cannot harden it from outside.

## What the hook payload looks like

The control plane normalizes hook payloads into a single shape regardless of harness:

```json
{
  "source": "claude-code",
  "event": "pre-tool",
  "harness_session_id": "…",
  "tool_use_id": "…",
  "tool": { "name": "Bash", "args": { "command": "..." } },
  "agent": { "model": "claude-opus-4-7", "user": "alice" }
}
```

Ledger leaves use the same shape plus `verdict`, `reason`, `policy_rule_id`, and `signer`.

For MCP-shaped tool names (`mcp__...` or `mcp_...`), pre-tool handlers also normalize HTTP MCP transport metadata into `tool.args.url` before policy evaluation when the harness exposes it. Candidate metadata keys are `url`, `server_url`, `mcp_server_url`, `transport_url`, and `base_url`; native `tool.args.url` takes precedence.

## Nudges in deny replies

When a matched rule carries a `nudge:` hint (see [Policies → Nudges](../guide/policies.md#nudges)) and the final verdict is `deny`, every harness shim — Claude Code, Codex, Cursor, Gemini — appends the hint to the deny reason it forwards to the model. The format is the literal string `"<reason>\n\n→ Suggested: <nudge>"` — arrow `→`, capital `S`, colon-space — and is intentionally stable so external tools can grep for `→ Suggested: ` to spot the hint. Allow, monitor-suppressed, and non-matching paths drop the field; the reason flows through unchanged.
