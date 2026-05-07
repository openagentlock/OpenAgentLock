# Dashboard

OpenAgentLock ships two surfaces over the same daemon endpoints:

- **Web dashboard** — a small SPA the control plane serves at `127.0.0.1:7879`. Shaped like a firewall admin UI: log table on the left, rule tree on the right, live activity at the bottom.
- **Terminal dashboard** — `agentlock dashboard`, an OpenTUI viewer over the daemon's JSON + SSE endpoints. Read-mostly today; edit flows still live on the web dashboard.

Both read from the same ledger and policy state — pick whichever fits the moment.

## What the web dashboard does

- **Log table** — every tool call across every harness, with per-row source / session / verdict / signer
- **Rule tree** — visual editor for the YAML policy with diff preview before save
- **Live activity** — Server-Sent Events feed; new entries stream in
- **"Block this next time"** — right-click any logged tool call to generate a starter rule from its shape, then refine
- **Mode toggle** — flip the daemon between `monitor` and `enforce` (separate from the policy file's own `mode`)
- **MCP pin queue** — accept or reject newly seen MCP servers

## What the terminal dashboard does

```bash
agentlock dashboard
# --daemon <url>   override control-plane base URL (env: AGENTLOCK_CONTROL_PLANE_URL)
# --token <token>  bearer token when AGENTLOCK_AUTH=password (env: AGENTLOCK_TOKEN)
```

- **Live ledger tail** — events stream in over SSE
- **Sessions** — open sessions with their signer tier and policy hash
- **Loaded gates** — the gates the daemon currently evaluates
- **Mode flip** — one keypress to toggle the daemon between `monitor` and `enforce`

Rule edits and the MCP pin queue still live on the web dashboard.

## Why two surfaces

Approval prompts in the hot path are user-hostile, so neither surface sits in the agent's flow. Both are where you spend time *between* agent sessions: reviewing what the agent did, tightening rules, and resolving MCP pin requests. The web dashboard is the full admin UI; the terminal dashboard is for when you'd rather not leave your shell.

## Access

The dashboard is bound to `127.0.0.1` only. There is no remote-admin mode. If you need to view the dashboard from a remote machine, port-forward via SSH:

```bash
ssh -L 7879:localhost:7879 user@host
open http://localhost:7879/
```

Authentication is currently password-based at the daemon. The dashboard reads the same auth mode (see [Authentication](auth.md)). OIDC / LDAP modes are stubbed but not yet wired.

## Embedded build

The dashboard is built with Vite and embedded into the Go binary via `go:embed`. There is no runtime Node dependency — you do not need Bun or npm to run the dashboard, only to develop it.
