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

The shim POSTs to `/v1/hooks/claude-code/<event>` and translates the response into Claude's exit-code / JSON contract. Routing through a shim — instead of Claude's native HTTP hooks — lets the harness fail-open silently on a daemon outage instead of surfacing a red "PreToolUse hook error / ECONNREFUSED" banner on every tool call. The first failed round-trip per outage emits a one-line stderr nudge ("daemon isn't running — running unprotected"), then stays silent until the daemon is back.

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

## Other harnesses

Cursor, OpenCode, Cline, Gemini CLI, Continue.dev all expose a hook surface but **the installer does not yet write to them**. The detectors find the harness, the picker shows it, and the install plan flags it as not yet implemented. Wiring is a follow-up tracked in the public roadmap.

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
