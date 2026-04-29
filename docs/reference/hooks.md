# Hooks

Each agent harness exposes a different shape of hook. OpenAgentLock targets each on its native terms.

## Claude Code

Claude Code uses HTTP hooks. The installer adds entries to `~/.claude/settings.json` pointing at the control plane:

```json
{
  "hooks": {
    "preTool": [{ "type": "http", "url": "http://127.0.0.1:7878/v1/hooks/claude-code/pre-tool" }],
    "postTool": [{ "type": "http", "url": "http://127.0.0.1:7878/v1/hooks/claude-code/post-tool" }]
  }
}
```

Cross-platform identical. No shell needed.

## Codex CLI

Codex uses **command hooks** declared in `~/.codex/config.toml`. The CLI ships an `agentlock hook codex <event>` shim so the same control-plane endpoints are reused:

```toml
codex_hooks = true

[[hook]]
event = "pre_tool"
command = ["agentlock", "hook", "codex", "pre-tool"]
```

The installer refuses to wire Codex without `codex_hooks = true` in your config; the flag is opt-in upstream.

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
