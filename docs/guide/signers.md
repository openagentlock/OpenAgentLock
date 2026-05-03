# Signers

Every ledger entry is signed. The strength of that signature is **opt-in**, ordered by friction. You pick once and the runtime stays silent — exactly one signature action happens at daemon startup.

## Available signer modes

| Mode | Strength | Friction at startup | Banner | Status |
|---|---|---|---|---|
| Unattested | None — no signature at all | Zero | Red: `UNATTESTED — LEDGER NOT SIGNED` | <span class="md-status-pill shipped">Shipped</span> |
| Software (dev / CI) | Low — keypair on disk | Zero | Red: `DEV — SOFTWARE SIGNER` | <span class="md-status-pill shipped">Shipped</span> |
| TOTP | Medium — software key unsealed by a 6-digit code | One TOTP entry | Yellow: `TOTP-BACKED — MEDIUM ASSURANCE` | <span class="md-status-pill shipped">Shipped</span> |
| OS keychain | High — keypair sealed by the OS | Zero (unlocked login keychain); one prompt otherwise | None | <span class="md-status-pill shipped">Shipped (macOS)</span> |
| Hardware key (YubiKey) | Strongest — PIV / FIDO2 | One tap | None | <span class="md-status-pill not-yet">Not yet implemented</span> |

Every ledger entry records its `signer` kind so verifiers can downgrade trust appropriately. Banners are intentionally alarming for weak modes — do not suppress them.

## How to enroll and use

=== "TOTP (recommended for prod)"

    One-time enrollment:

    ```bash
    agentlock signer enroll --tier totp --passphrase 'your-passphrase-here'
    ```

    The CLI prints an `otpauth://` URI; scan it with any RFC 6238 authenticator (Google Authenticator, Authy, 1Password, Bitwarden, etc.).

    From then on, mint sessions with the current 6-digit code from your authenticator:

    ```bash
    # used by `install`, `uninstall`, `session create`, `session rotate`
    agentlock install --tier totp --code 123456 --passphrase 'your-passphrase-here'
    agentlock session create --tier totp --code 123456 --passphrase 'your-passphrase-here'
    ```

    Ledger entries get the yellow `TOTP-BACKED — MEDIUM ASSURANCE` banner.

=== "OS keychain (macOS)"

    One-time enrollment stashes a fresh ed25519 seed in the macOS login keychain via `/usr/bin/security add-generic-password`. The CLI keeps a small meta file under `$AGENTLOCK_HOME/os-keychain.meta.json` with the pubkey and (optionally) an expiry timestamp.

    ```bash
    # no expiry
    agentlock signer enroll --tier os-keychain

    # expires after 4 hours (good for ephemeral dev sessions)
    agentlock signer enroll --tier os-keychain --ttl 4h
    ```

    `--ttl` accepts compound durations: `30m`, `4h`, `7d`, `1h30m`, `90s`. The TTL is enforced by the CLI before each `session create` — once expired, you re-enroll. macOS Keychain itself has no native TTL, so the keychain entry persists until the next `--tier os-keychain` enroll overwrites it (`-U` to `security`).

    Mint sessions with no extra flags:

    ```bash
    agentlock session create --tier os-keychain
    agentlock session rotate --id <session-id> --tier os-keychain
    ```

    Ledger entries get `signer=os_keychain` and currently no banner — strength is "as strong as your login keychain". Linux Secret Service / Windows DPAPI are not yet implemented; the CLI errors out clearly on those platforms.

=== "Software (dev / CI only)"

    No enrollment step — the keypair is created lazily on first session mint, sealed with file permissions.

    ```bash
    agentlock install --tier software
    agentlock session create --tier software
    ```

    The CLI **and the daemon** both refuse the software signer unless `AGENTLOCK_ALLOW_SOFTWARE_SIGNER=1` is set on whichever side is rejecting it. Release builds intentionally drop that env knob from the user-facing surface.

=== "Unattested (no signature)"

    Useful for getting a feel for the install/uninstall flow during evaluation. The daemon refuses unattested sessions unless explicitly allowed:

    ```bash
    docker rm -f agentlock
    docker run -d --name agentlock \
      -p 127.0.0.1:7878:7878 -p 127.0.0.1:7879:7879 \
      -v "$HOME/.agentlock:/var/lib/agentlock" \
      -e AGENTLOCK_ALLOW_UNATTESTED=1 \
      ghcr.io/openagentlock/agentlockd:latest

    agentlock install        # default tier is unattested
    ```

    Ledger entries get the red `UNATTESTED — LEDGER NOT SIGNED` banner. Not recommended outside investigative / read-only deployments.

## How signatures are produced

- The CLI on the host owns the long-lived key (TOTP-unlocked or hardware key).
- At daemon startup, the CLI signs a freshly minted **session key** and posts the signed bundle to `POST /v1/sessions`.
- The control plane uses the session key to sign individual ledger leaves in memory; the long-lived key never crosses the trust boundary.
- Sessions are short-lived. When a session expires, the next ledger append fails, the CLI re-prompts (or re-taps), and a new session is minted.

The wire shape lives at `POST /v1/sessions/create`, `GET /v1/sessions`, `POST /v1/sessions/heartbeat`. See [HTTP API](../reference/api.md).

## Why signing happens at daemon startup, not per-call

Approval prompts in the hot path of an agent loop are user-hostile and create [decision fatigue](https://en.wikipedia.org/wiki/Decision_fatigue) — users reflexively click through. We sign a session at start, then sign every ledger leaf with the session key automatically. The audit trail is still tied to your hardware tap because the session key itself was signed by it.

## Hardware-key plans

When the hardware-key signer ships:

- **macOS / Linux** — PIV slot 9c via PC/SC, fallback to FIDO2 / U2F
- **Windows** — Yubico Smart Card Minidriver + PC/SC (native on Windows 10/11)

YubiKey will **not** work inside Docker Desktop on macOS or Windows — USB HID is not bridged into Linux containers. The CLI on your host does the tap, signs the session, and the daemon (in Docker) only ever sees session-scoped keys. This is by design.

## Banners and policy interaction

Some policy rules can require a strong signer to be present:

```yaml
gates:
  - id: rogue.destructive-bash
    when:
      command_regex: 'rm -rf|DROP TABLE'
    on_hit: deny
    require_strong: true   # refuses unattested / OS-keychain / TOTP sessions
```

When `require_strong: true` is set, sessions whose `signer` field does not satisfy the requirement get `deny` regardless of any other allow.
