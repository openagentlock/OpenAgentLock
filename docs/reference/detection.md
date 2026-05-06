# Detection registry

The CLI ships with eight harness detectors. Each is a small TypeScript module under `cli/src/detect/` exporting a `Detector` interface and registered in `cli/src/detect/index.ts`.

## What detection does

`agentlock detect` walks the registry and asks each detector "are you installed on this host, and if so, where is your config?" Each detector can probe:

- Filesystem locations (cross-platform via `cli/src/util/paths.ts`)
- Binary presence on `PATH`
- Harness-specific config files (`~/.claude/settings.json`, `~/.codex/config.toml`, etc.)

The result is a small struct with `name`, `present`, `surfaces`, `configPaths`, and `version` (best-effort).

## Currently registered detectors

| Detector | File | Hook surface |
|---|---|---|
| Claude Code | `claude-code.ts` | HTTP hooks |
| Codex CLI | `codex.ts` | command hooks (TOML) |
| Cursor | `cursor.ts` | hook surface present |
| OpenCode | `opencode.ts` | hook surface present (MCP gap, see [MCP](../guide/mcp.md)) |
| Cline | `cline.ts` | hook surface present |
| Continue.dev | `continue-dev.ts` | hook surface present |
| Gemini CLI | `gemini.ts` | hook surface present |
| VS Code Copilot | `vscode-copilot.ts` | none today |

## Wiring vs detection

A harness being **detected** is independent of whether the installer will **wire it up**. Today, `agentlock install` wires Claude Code, Codex CLI, Cursor, and Gemini CLI. The other detectors land in the picker but the installer flags them as not yet implemented and skips writing hook entries.

## Adding a new harness detector

1. Drop a new file under `cli/src/detect/` exporting a `Detector`. Use `claude-code.ts` as the smallest reference.
2. Register it in `cli/src/detect/index.ts` so `detectAll()` picks it up.
3. Set `surfaces: ["none-known"]` if there is no integration path; the install selector will disable that row.
4. Add a regression test under `cli/tests/detect.test.ts`.

Full implementation follow-up to wire it through the installer is a separate piece of work and not part of detection itself.
