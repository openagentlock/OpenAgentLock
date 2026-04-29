# Local web dashboard

The control plane serves a small SPA at `127.0.0.1:7879`. It is shaped like a firewall admin UI — log table on the left, rule tree on the right, live activity at the bottom.

## What it does

- **Log table** — every tool call across every harness, with per-row source / session / verdict / signer
- **Rule tree** — visual editor for the YAML policy with diff preview before save
- **Live activity** — Server-Sent Events feed; new entries stream in
- **"Block this next time"** — right-click any logged tool call to generate a starter rule from its shape, then refine
- **Mode toggle** — flip the daemon between `monitor` and `enforce` (separate from the policy file's own `mode`)
- **MCP pin queue** — accept or reject newly seen MCP servers

## Why a separate UI

The TUI on your terminal is for setup. Once installed, you should not see it during your agent loop. Approval prompts in the hot path are user-hostile; we keep them out of the agent's flow on purpose.

The web dashboard is where you spend time *between* agent sessions: reviewing what the agent did, tightening rules, and resolving MCP pin requests.

## Access

The dashboard is bound to `127.0.0.1` only. There is no remote-admin mode. If you need to view the dashboard from a remote machine, port-forward via SSH:

```bash
ssh -L 7879:localhost:7879 user@host
open http://localhost:7879/
```

Authentication is currently password-based at the daemon. The dashboard reads the same auth mode (see [Authentication](auth.md)). OIDC / LDAP modes are stubbed but not yet wired.

## Embedded build

The dashboard is built with Vite and embedded into the Go binary via `go:embed`. There is no runtime Node dependency — you do not need Bun or npm to run the dashboard, only to develop it.
