# Architecture overview

Three languages, one repo, three trust shapes.

## Components

| Component | Language | Runtime | Trust role |
|---|---|---|---|
| `cli/` | TypeScript | Bun, on the host | Owns the long-lived signing key. Talks to harness configs. Renders the TUI. |
| `control-plane/` | Go | Docker, `127.0.0.1:7878` | Evaluates policy. Drives install plan/apply. Appends to ledger. |
| `ledger/` | Rust | linked into Go via FFI | Single source of truth for Merkle correctness and verification. |

## Why three languages

- **TypeScript / Bun** for the CLI because the harness landscape (Claude Code, Cursor, Codex, …) is JavaScript-friendly, OpenTUI is great, and we want fast install paths and zero extra runtime on developer laptops.
- **Go** for the control plane because it is the boring sweet spot for an HTTP service with concurrent hooks, an SSE stream, and a single-writer ledger appender. Stdlib is enough — no router framework.
- **Rust** for the ledger because cryptographic correctness is the one place we cannot afford "two implementations slowly drifting." The Go control plane links the Rust crate via CGO so verification logic exists in exactly one place.

## Data flow

```
[ harness ] → hook → [ control plane ] → [ ledger ] → [ disk + signature ]
                          │                                 │
                          └─→ verdict ─→ [ harness ]        │
                                                            ▼
                                                  [ /v1/ledger/* + dashboard ]
```

A pre-tool hook lands at the control plane. The plane:

1. Resolves harness + session + tool-call identity.
2. Walks the policy. Evaluator returns `allow | deny | skip` against each gate.
3. Appends a leaf describing the call and the verdict to the ledger.
4. Returns the verdict to the harness.

Steps 3 and 4 happen in that order: the audit record is durable before the harness gets its answer.

## Cross-harness consistency

A single user typically has multiple harnesses installed concurrently — Claude Code + Cursor + Codex all coexist on the same box. Each ledger entry carries:

- `source` — the harness's name (`claude-code`, `cursor`, `codex`, `opencode`, `cline`, `continue`, `gemini`, `copilot`, plus `tui` / `system`)
- `harness_session_id` — the harness's own session / conversation id
- `tool_use_id` — the harness's per-call id (idempotency key)

One signer enrollment covers every harness. Policy applies uniformly across every source.

## What is not in this repo

- **No LLM in the policy evaluator.** Rules are deterministic YAML.
- **No "auto-approve on repeat" shortcut.** Every signer event is an explicit user action.
- **No telemetry.** The daemon binds to `127.0.0.1` only. Nothing leaves the host.
- **No remote control plane today.** Multi-tenant / on-prem deployment is roadmap, not shipped — see [Authentication](../guide/auth.md).
