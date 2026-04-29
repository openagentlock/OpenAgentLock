# Signers

Every ledger entry is signed. The strength of that signature is **opt-in**, ordered by friction. You pick once and the runtime stays silent — exactly one signature action happens at daemon startup.

## Available signer modes

| Mode | Strength | Friction at startup | Banner | Status |
|---|---|---|---|---|
| Unattested | None — no signature at all | Zero | Red: `UNATTESTED — LEDGER NOT SIGNED` | <span class="md-status-pill shipped">Shipped</span> |
| Software (dev / CI) | Low — keypair on disk | Zero | Red: `DEV — SOFTWARE SIGNER` | <span class="md-status-pill shipped">Shipped</span> |
| TOTP | Medium — software key unsealed by a 6-digit code | One TOTP entry | Yellow: `TOTP-BACKED — MEDIUM ASSURANCE` | <span class="md-status-pill shipped">Shipped</span> |
| OS keychain | High — keypair sealed by the OS | Zero | None | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Hardware key (YubiKey) | Strongest — PIV / FIDO2 | One tap | None | <span class="md-status-pill not-yet">Not yet implemented</span> |

Every ledger entry records its `signer` kind so verifiers can downgrade trust appropriately. Banners are intentionally alarming for weak modes — do not suppress them.

## How to enroll

=== "TOTP"

    ```bash
    agentlock signer enroll --tier totp
    ```

    The CLI prints a `otpauth://` URI and a QR code; scan it with any RFC 6238 authenticator (Google Authenticator, Authy, 1Password, Bitwarden, etc.). A 6-digit code is requested at daemon startup.

=== "Software (dev only)"

    ```bash
    AGENTLOCK_ALLOW_SOFTWARE_SIGNER=1 agentlock signer enroll --tier software
    ```

    The CLI refuses without the explicit `AGENTLOCK_ALLOW_SOFTWARE_SIGNER=1` opt-in. Release builds drop the env var entirely.

=== "Unattested"

    ```bash
    agentlock signer enroll --tier unattested
    ```

    Not recommended outside investigative / read-only deployments.

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
