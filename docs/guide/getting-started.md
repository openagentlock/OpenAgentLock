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
      -v agentlock-state:/var/lib/agentlock \
      -p 127.0.0.1:7878:7878 \
      -p 127.0.0.1:7879:7879 \
      ghcr.io/openagentlock/agentlockd:latest
    ```

    The CLI runs on your host and is the only process that touches host configs (`~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.cursor/hooks.json`); the daemon never reads or writes there, so no bind mount is needed. State lives in the `agentlock-state` named volume.

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
    git clone https://github.com/openagentlock/OpenAgentLock
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

This prints a table of every agent harness it found on your machine. Today, end-to-end hooks are wired for **Claude Code**, **Codex CLI**, and **Cursor**; other harnesses are detected but the installer flags them as not yet implemented. See [Status](../status.md).

Then pick a signer tier and run `install`. Two recommended paths:

=== "Production: TOTP-attested (recommended)"

    For ledger-signed entries you need an attested signer (TOTP / hardware key). Install accepts unattested sessions for the file-writing step, but ledger entries from those sessions get the red `UNATTESTED` banner. Enroll a TOTP signer once, then use it for `install`:

    ```bash
    # 1. one-time enrollment — pick a passphrase, scan the QR with your authenticator
    agentlock signer enroll --tier totp --passphrase 'your-passphrase-here'
    # the CLI prints an otpauth:// URI; scan it with Google Authenticator,
    # 1Password, Authy, Bitwarden, etc.

    # 2. install with a TOTP-attested session
    agentlock install --tier totp --code 123456 --passphrase 'your-passphrase-here'
    # 123456 is the current 6-digit code from your authenticator app.
    ```

    Ledger entries get the yellow `TOTP-BACKED — MEDIUM ASSURANCE` banner.

=== "Dev / quick eval: unattested"

    Useful for getting a feel for the install/uninstall flow without setting up a signer. Allow unattested sessions on the daemon:

    ```bash
    docker rm -f agentlock
    docker run -d --name agentlock \
      -e AGENTLOCK_ALLOW_UNATTESTED=1 \
      -v agentlock-state:/var/lib/agentlock \
      -p 127.0.0.1:7878:7878 -p 127.0.0.1:7879:7879 \
      ghcr.io/openagentlock/agentlockd:latest

    agentlock install        # default tier is unattested
    ```

    Ledger entries get the red `UNATTESTED — LEDGER NOT SIGNED` banner. Don't use in prod.

=== "Dev / CI: software signer"

    Software signer reads/writes a keypair on disk; the daemon refuses it unless `AGENTLOCK_ALLOW_SOFTWARE_SIGNER=1`. Intended for dev/CI only.

    ```bash
    agentlock install --tier software
    ```

Pick the harnesses to harden, review the diff, confirm. The installer writes harness-specific configuration (e.g. `~/.claude/settings.json` hook entries, `~/.codex/hooks.json`, plus `codex_hooks = true` in `~/.codex/config.toml` — auto-set on first install, with a backup of the original) and registers a clean rollback path you can invoke later with `agentlock uninstall`.

Open the dashboard at <http://127.0.0.1:7879/> to watch live activity.

## What happens next

Out of the box, the control plane runs in **monitor mode**: every tool call is logged but nothing is blocked. Use the dashboard to review activity, then flip rules to enforce when you're confident. See [Policies and the five gates](policies.md).

OS-keychain and hardware-key (YubiKey) signers are stronger than TOTP and are on the roadmap; today TOTP is the strongest signer that ships. See [Signers](signers.md).
