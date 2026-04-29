# Threat model

What OpenAgentLock defends, what it does not, and where the trust boundaries are.

## Adversaries we care about

1. **Compromised dependency** — an LLM-suggested package, an MCP server, or a transitive transitively pulls in code that calls home, exfiltrates secrets, or rewrites your tree.
2. **Prompt-injection-driven agent** — an attacker plants instructions in a file, a comment, or a tool result that the agent reads, and the agent then runs commands the user did not ask for.
3. **Confused-deputy harness** — the harness itself behaves correctly but its trust surface is wider than the user realizes (e.g. an MCP server they forgot they enabled three months ago).

## What OpenAgentLock defends

- **Pre-execution gating.** Tool calls are evaluated before the harness runs them. A `deny` does not get to "almost happen and then unwind."
- **Tamper-evident audit.** Every decision is hashed, signed, and committed to the local Merkle ledger. Any later modification changes the root.
- **Cross-harness consistency.** One policy, one ledger, one signer enrollment — applied uniformly across Claude Code, Codex CLI, Cursor, etc. as those harnesses come online.
- **Locality.** Nothing leaves your machine by default. The control plane binds to `127.0.0.1` only. There is no telemetry.

## What OpenAgentLock does not defend

- **A compromised host.** If the attacker already has root, OpenAgentLock cannot tell you that — the daemon, the ledger, and your harness all sit downstream of host trust.
- **Already-resident malware.** We hook the harness, not the OS. A backdoor running in another process is not in our path.
- **Network-layer attacks.** TLS does the wire job; we do the record job.
- **Misconfiguration of the harness itself.** If you tell Claude Code to skip permissions checks, our hooks still fire, but the trust shape is your call.
- **Side-channel exfiltration via permitted channels.** If you allow `curl` to your blog, an agent can write a poem that encodes secrets in adjective choice. Policy is necessary, not sufficient.

## Trust boundaries

```
┌──────────────────────────────────────────────────────────────────────┐
│  HOST  (you, your shell, your filesystem, your keychain)             │
│                                                                      │
│  ┌─────────────────────┐         ┌────────────────────────────────┐  │
│  │  agent harness      │  hook   │  agentlock CLI                 │  │
│  │  (Claude Code, …)   │ ──────▶ │  (owns long-lived signing key) │  │
│  └─────────────────────┘         └────────────────────────────────┘  │
│                                              │                       │
└──────────────────────────────────────────────┼───────────────────────┘
                                               │ session-scoped key
                                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE  (Docker container, 127.0.0.1:7878 / :7879)           │
│                                                                      │
│  policy ──▶ ledger ──▶ dashboard                                     │
└──────────────────────────────────────────────────────────────────────┘
```

The CLI on the host owns the long-lived key (TOTP-unlocked or hardware key). It signs a short-lived **session key** at startup and posts the signed bundle to the daemon. The daemon signs ledger leaves with the session key in memory. The long-lived key never crosses into the container.

YubiKey deliberately does **not** work inside Docker. USB HID is not bridged into Linux containers. The split is by design.

## Failure modes by category

| Failure | Effect | Mitigation |
|---|---|---|
| Daemon dies mid-call | Harness sees a hook timeout; harness's own default applies. We never fail-open in our control. | Restart the daemon, run `agentlock ledger verify` |
| Session expires under load | Next ledger append fails until the CLI re-signs a session | Reduce session TTL to fit your tap cadence |
| Policy file syntax error | `mode` defaults to monitor; nothing blocks | The dashboard validates before save; CI also lints |
| Long-lived key compromise | All sessions signed under that key are suspect | Rotate, then mark prior ledger range as untrusted in audit |
