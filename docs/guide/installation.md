# Installation

OpenAgentLock has two pieces:

- the **CLI** (`agentlock`) — runs on your host
- the **control plane** — runs in a Docker container

Both are required. The CLI on its own can probe for harnesses but cannot evaluate policy or write to the ledger.

## CLI

### npm / Bun

```bash
# global install
bun add -g @openagentlock/cli
# or
npm i -g @openagentlock/cli
```

The package ships TypeScript source; Bun runs it directly via the `agentlock` shim.

### From source

```bash
git clone https://github.com/openagentlock/OpenAgentLock
cd openagentlock/cli
bun install
bun link        # makes `agentlock` available on your PATH
```

## Control plane (Docker)

### `docker compose` (recommended)

```bash
curl -O https://raw.githubusercontent.com/openagentlock/openagentlock/main/docker-compose.yml
docker compose up -d
```

The compose file references `ghcr.io/openagentlock/agentlockd:latest` and binds two loopback ports:

- `127.0.0.1:7878` — CLI and hook traffic
- `127.0.0.1:7879` — local web dashboard

State is persisted in a named Docker volume (`agentlock-state`) so ledger entries survive restarts.

### `docker run`

```bash
docker run -d --name agentlock \
  -v agentlock-state:/var/lib/agentlock \
  -p 127.0.0.1:7878:7878 \
  -p 127.0.0.1:7879:7879 \
  ghcr.io/openagentlock/agentlockd:latest
```

Daemon state lives in the `agentlock-state` named volume (Docker copies the image's owner/mode on first mount, so no host-side `chown` is needed). The CLI runs on your host and is the only process that writes harness configs (`~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.cursor/hooks.json`); the daemon never reads or writes those paths, so no bind mount is needed.

If you previously bind-mounted to `$HOME/.agentlock`, your data is still there. Migrate it with:

```bash
docker run --rm \
  -v "$HOME/.agentlock:/from" -v agentlock-state:/to \
  alpine cp -a /from/. /to/
```

### Image tags

| Tag | Meaning |
|---|---|
| `:latest` | newest commit on `main` (rolling) |
| `:0.x.y` | tagged release |
| `:0.x` | tracks the latest patch on a minor line |
| `:sha-abcdef0` | pinned to a specific commit |

We sign images with cosign keyless on every release; verify with `cosign verify ghcr.io/openagentlock/agentlockd:<tag>`.

## Platform support

| Platform | CLI | Control plane | Hardware-key signer |
|---|---|---|---|
| macOS 13+ | yes | yes (Docker Desktop / OrbStack / Colima) | yes |
| Linux x86_64 / arm64 | yes | yes | yes |
| Windows 10 1809+ / 11 (native) | yes | Docker Desktop | yes (PC/SC + Yubico minidriver) |
| Windows + WSL2 | yes | yes | YubiKey not bridged into Linux containers — use the host CLI |

See [Windows notes](windows.md) for platform specifics.

## Uninstall

```bash
agentlock uninstall                  # removes harness hook entries
docker compose down -v               # stops the control plane and drops state (irreversible)
brew uninstall agentlock             # or `npm uninstall -g @openagentlock/cli`
```
