# Policies and the five gates

OpenAgentLock policy is **deterministic YAML**. No LLM lives inside the evaluator. A rule is a path-shape match plus a verdict. Verdicts are `allow`, `deny`, or `skip` — there is **no** `ask` verdict in the default path, and the schema rejects it at load time.

## Two switches: `mode` and rule actions

Two things determine whether a tool call is blocked:

1. **Top-level `mode`** at the root of your policy file: `monitor` or `enforce`. Without `mode: enforce`, every matched rule is downgraded to `allow` regardless of evaluator output.
2. **Per-rule action** (`on_hit`, `on_miss`).

`PATCH /v1/mode` toggles a separate daemon-level switch and does **not** override the policy's own `mode`.

## The five baseline gates

Every install ships `policies/default.yaml` with five gates in monitor mode:

<div class="gate-grid" markdown>

<div class="gate-card" markdown>
#### Package install
<span class="gate-id">`supply-chain.pkg-install`</span>

`pip install`, `npm install`, `brew install`, `cargo install`. Catches typosquats and build-time exfiltration.
</div>

<div class="gate-card" markdown>
#### Untrusted MCP
<span class="gate-id">`supply-chain.untrusted-mcp`</span>

MCP server with an unpinned public key. Fingerprints land in `/v1/mcp/pin`.
</div>

<div class="gate-card" markdown>
#### Secret reads
<span class="gate-id">`rogue.secret-read`</span>

Reads of `.env`, `~/.ssh`, `~/.aws/credentials`, anywhere a secret-shaped path appears in the command.
</div>

<div class="gate-card" markdown>
#### Network egress
<span class="gate-id">`rogue.net-egress`</span>

`curl`, `wget`, MCP HTTP tools. Pre-execution.
</div>

<div class="gate-card" markdown>
#### Destructive bash
<span class="gate-id">`rogue.destructive-bash`</span>

`rm -rf`, `git push --force`, `DROP TABLE`, `kubectl delete`.
</div>

</div>

## Authoring rules

Two rules of thumb:

> **Match on path shape, not on reader name.** A rule like `(cat|head|grep)\s+.*\.env` is bypassable by the agent picking `sed`, `awk`, `xxd`, or `python`. Prefer `(\.env(\b|[._-])|/\.ssh(/|\b)|/\.aws(/|\b)|credentials)` — the secret-shaped path token alone, anywhere in the command.

> **Use the dashboard.** The local web dashboard (`127.0.0.1:7879`) lets you right-click a logged tool call and "block this next time" — it generates a starter rule from the call's shape. Iterate from there.

## Authoring via the dashboard

Open <http://127.0.0.1:7879/>. The dashboard is shaped like a firewall admin UI:

- **Log table** — every tool call across every harness, filterable by source/session/verdict
- **Rule tree** — visual editor for the YAML policy
- **Live activity** — SSE feed; new entries stream in

Changes are validated against the policy schema before being written, and a snapshot of the previous policy is saved so you can revert.

## Policy schema

The full schema lives in [`api/openapi.yaml`](https://github.com/openagentlock/OpenAgentLock/blob/main/control-plane/api/openapi.yaml) under `components.schemas.Policy`. Minimal example:

```yaml
mode: monitor

evaluator:
  on_miss: allow
  on_hit: deny

gates:
  - id: rogue.secret-read
    when:
      command_regex: '(\.env(\b|[._-])|/\.ssh(/|\b)|/\.aws(/|\b)|credentials)'
    on_hit: deny
    severity: high
```

## Enforcement vs monitor

- **Monitor** — every gate matches but the verdict is downgraded to `allow` for the harness. Use this on day one.
- **Enforce** — the verdict is honored. Switch on per-gate first if you want to ramp gradually; the schema permits a `mode` field on individual rules to override the global setting.
