# Isolation

OpenAgentLock has rules about where it writes. None of them touch your real harness configuration directories.

## Where state goes

- `${AGENTLOCK_HOME:-$HOME/.agentlock}` — control-plane SQLite ledger, pinned MCP public keys, session keys.
- `${CLAUDE_CONFIG_DIR:-$HOME/.claude}` — Claude Code's own settings file. The installer adds hook entries here on `agentlock install`, removes them on `agentlock uninstall`.
- `~/.codex/config.toml` — Codex CLI's own settings file. Same plan-apply-uninstall contract.

These two files are the only paths we modify inside the harnesses' territory. The installer never touches anything else under `~/.claude` or `~/.codex` — only the hook entries it added.

The control-plane Docker volume mounts `agentlock-state` into `/var/lib/agentlock`. Your host's `~/.agentlock` is the natural mount target if you prefer a bind mount over a named volume.

## What we do not touch

- The OS keychain / Windows Credential Manager / Linux Secret Service — except via the future OS-keychain signer, which writes a single keypair entry under `openagentlock`.
- Other harness directories (`~/.cursor`, `%APPDATA%\Cursor`, etc.) until that harness is wired and the user opts in via `agentlock install`.

## Development isolation

For maintainers: the development checkout out of the GitHub repo runs with isolated paths so your real harness configs stay clean while testing:

- `CLAUDE_CONFIG_DIR=./dev/.claude`
- `AGENTLOCK_HOME=./dev/agentlock`

A `scripts/doctor.sh` check refuses to run if either path resolves into your real harness config dirs.

If you contribute, be careful never to hard-code `$HOME/.claude` or `%USERPROFILE%\.claude` anywhere — go through the path helpers.
