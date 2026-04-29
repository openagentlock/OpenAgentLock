# Getting started

Three steps to a hardened agent loop:

1. Run the control plane (Docker)
2. Install the CLI
3. Wire the CLI into your agent harnesses

## 1. Run the control plane

The control plane is a small Go HTTP service that lives in a Docker container. It evaluates policy, drives install plan/apply, and signs every decision into the ledger.

=== "docker compose"

    ```bash
    curl -O https://raw.githubusercontent.com/openagentlock/openagentlock/main/docker-compose.yml
    docker compose up -d
    ```

=== "docker run"

    ```bash
    docker pull ghcr.io/openagentlock/agentlockd:latest
    docker run -d --name agentlock \
      -p 127.0.0.1:7878:7878 \
      -p 127.0.0.1:7879:7879 \
      -v "$HOME/.agentlock:/var/lib/agentlock" \
      ghcr.io/openagentlock/agentlockd:latest
    ```

The service binds to `127.0.0.1:7878` (CLI / hook traffic) and `127.0.0.1:7879` (local web dashboard). Neither port should ever be exposed to a non-loopback interface.

Verify it is up:

```bash
curl -s http://127.0.0.1:7878/v1/health
# {"status":"ok","version":"…"}
```

## 2. Install the CLI

=== "Homebrew"

    ```bash
    brew install openagentlock/tap/agentlock
    ```

=== "npm / Bun"

    ```bash
    bun add -g @openagentlock/cli
    # or
    npm i -g @openagentlock/cli
    ```

=== "From source"

    ```bash
    git clone https://github.com/openagentlock/openagentlock
    cd openagentlock/cli
    bun install
    bun link
    ```

Verify:

```bash
agentlock --help
```

## 3. Wire it up

```bash
agentlock detect
```

This prints a table of every agent harness it found on your machine. Today, end-to-end hooks are wired for **Claude Code** and **Codex CLI**; other harnesses are detected but the installer flags them as not yet implemented. See [Status](../status.md).

Then:

```bash
agentlock install
```

Pick the harnesses you want to harden, review the diff, confirm. The installer writes harness-specific configuration (e.g. `~/.claude/settings.json` hook entries, `~/.codex/config.toml` `codex_hooks`) and registers a clean rollback path you can invoke later with `agentlock uninstall`.

Open the dashboard at <http://127.0.0.1:7879/> to watch live activity.

## What happens next

Out of the box, the control plane runs in **monitor mode**: every tool call is logged but nothing is blocked. Use the dashboard to review activity, then flip rules to enforce when you're confident. See [Policies and the five gates](policies.md).

Optionally enroll a stronger signer (TOTP today, OS keychain and YubiKey on the way) so ledger entries are signed with something other than a software key. See [Signers](signers.md).
