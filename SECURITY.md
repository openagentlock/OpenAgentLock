# Security policy

## Reporting a vulnerability

Email **security@openagentlock.dev** with a description, reproduction steps, and impact assessment. We will acknowledge within 72 hours.

Do not open public issues for vulnerabilities.

## Scope

In scope:

- The CLI (`cli/`)
- The control plane (`control-plane/`)
- The ledger crate (`ledger/`)
- The published `ghcr.io/openagentlock/control-plane` Docker image
- The published `@openagentlock/cli` npm package

Out of scope:

- Misconfigurations of agent harnesses themselves (Claude Code, Cursor, Codex CLI, etc.)
- Issues that require an attacker who already controls the host
- Reports based on outdated dependencies without a working exploit

## Disclosure

Once a fix lands and a release is cut, we will:

1. Publish a GitHub Security Advisory with a CVE if applicable.
2. Credit the reporter unless they request anonymity.
3. Note the fix version in `CHANGELOG.md`.

## Cryptographic posture

- Ledger: Ed25519 over SHA-256 Merkle leaves, RFC 6962 odd-tail handling, RFC 8785 JCS canonicalization for signed payloads.
- Hardware-key signer: PIV / FIDO2 via the host CLI; YubiKey not bridged into Docker (USB HID limitation).
- TOTP signer: RFC 6238, 6-digit, default 30-second step.

If you believe any of these primitives are misused or the chosen parameters are insufficient, please file a report.
