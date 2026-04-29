# FAQ

## Does this slow my agent down?

The hook adds one round trip to `127.0.0.1:7878` per tool call. In practice that is dominated by the agent's own LLM latency. If you measure regressions, file an issue with timing data and a sample of the affected tool call.

## Does it phone home?

No. The control plane binds to `127.0.0.1` only. There is no telemetry, no analytics, no remote service to contact. The CLI ships TypeScript source you can read.

## Can I run it without Docker?

You can build and run the control plane natively (`go build -o control-plane ./cmd/control-plane` after building the Rust ledger). Most users prefer the Docker image because it bundles the Rust ledger staticlib for you and isolates the daemon.

## Why not just use the harness's own permissions UI?

Two reasons:

1. **Cross-harness consistency.** A user on Claude Code + Cursor + Codex has three permission UIs with three different shapes. We give them one policy file, one ledger, one signer enrollment.
2. **Audit.** The harness's permission UI does not produce a tamper-evident record of what the agent did. The ledger does.

## Why don't I get a popup when something risky happens?

Approval prompts in the hot path of an agent loop are user-hostile. Users reflexively click through them. We ship monitor mode by default so you can review activity in the dashboard between sessions and tighten rules at your own pace. See [Policies](guide/policies.md).

## Why a Merkle ledger and not just a log file?

Tamper-evidence and offline verification. Anyone with the public key + a leaf + an inclusion proof can prove the leaf was committed at a given sequence without contacting the daemon. A plain log file gives you neither.

## Why three languages?

Each piece sits at the language's sweet spot: TypeScript for harness-facing CLI / TUI, Go for the HTTP service, Rust for cryptographic correctness. The ledger is in Rust *because* we want exactly one implementation of the verification path; it is linked into Go via FFI. See [Architecture overview](architecture/overview.md).

## What's the license?

[Functional Source License 1.1, with Apache 2.0 conversion after 2 years](https://fsl.software/). See `LICENSE` in the repo. Any non-competitive use is permitted. The license auto-converts to Apache 2.0 two years after each release.

## How do I report a security issue?

Use **GitHub's private vulnerability reporting**: <https://github.com/openagentlock/OpenAgentLock/security/advisories/new>. Do **not** open a public issue with reproduction details. See [`SECURITY.md`](https://github.com/openagentlock/openagentlock/blob/main/SECURITY.md).

## What's coming next?

The [status page](status.md) lists what is shipped vs not yet implemented. Higher-friction signers (OS keychain, hardware key) come first; OIDC / RBAC / on-prem federation follows.
