# Windows notes

OpenAgentLock supports Windows 10 1809+ and Windows 11, both native PowerShell and WSL2.

## CLI

The CLI runs on Bun, which works natively on Windows. `bun add -g @openagentlock/cli` installs the `agentlock` shim on your `PATH`. Native PowerShell is a first-class target.

If you prefer WSL2, install Bun inside the WSL2 distro and run the CLI there. Path detection follows the WSL filesystem (`~/.claude` etc.) — not your Windows host's `%USERPROFILE%`.

## Control plane (Docker)

Docker Desktop on Windows works fine. **Use the WSL2 backend** (the default). The control plane image is `linux/amd64` and `linux/arm64`; both run under Docker Desktop's hypervisor.

If you bind-mount a host directory into the control-plane container, **keep the path inside the WSL2 filesystem** (e.g. `\\wsl$\Ubuntu\home\you\.agentlock`), not a Windows path like `C:\Users\you\.agentlock`. Bind mounts of Windows host paths into Linux containers are known to be flaky on Docker Desktop ([docker/for-win#13014](https://github.com/docker/for-win/issues/13014)). Named volumes (the default in our published `docker-compose.yml`) sidestep this entirely.

## Hooks transport

Claude Code hooks use HTTP, which is identical on Windows. No special configuration.

Codex CLI hooks use **command** hooks. The CLI ships an `agentlock hook codex <event>` shim that hooks into the daemon over HTTP — works on Windows out of the box.

## OS-keychain signer

When the OS-keychain signer ships, Windows uses **Credential Manager** (Generic credential, scoped to `openagentlock`). The Rust `keyring` crate handles this transparently.

## Hardware-key signer (YubiKey)

When the hardware-key signer ships, Windows uses **PC/SC** with the **Yubico Smart Card Minidriver** — both native on Windows 10 and 11.

YubiKey **will not work** inside Docker Desktop on Windows. USB HID is not bridged into Linux containers. The CLI on your host owns the YubiKey, signs a session, and the daemon (in Docker) only ever sees session keys. The split is identical to macOS.

If you want USB-HID bridging for some other reason, look into [usbipd-win](https://github.com/dorssel/usbipd-win) — but bridging YubiKey through it requires a custom WSL2 kernel, which is out of scope for OpenAgentLock support.

## Known issues

- `docker compose up` may take 30+ seconds on first run while WSL2 spins up. Subsequent starts are fast.
- If the dashboard at `http://127.0.0.1:7879/` returns "connection refused" but the container is running, check Windows firewall — Docker Desktop sometimes asks for permission on first bind.
