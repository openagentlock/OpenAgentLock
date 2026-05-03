# Policies and rules

OpenAgentLock policy is **deterministic YAML**. No LLM lives inside the evaluator. A rule (called a *gate* in the YAML schema) is a path-shape match plus a verdict. Verdicts are `allow`, `deny`, or `skip` — there is **no** `ask` verdict in the default path, and the schema rejects it at load time.

Most operators do not author policies from scratch. The shape of a real-world policy is:

1. The **five built-in defaults** the daemon boots with — useful baseline, intentionally narrow.
2. A handful of **community rules** pulled from [openagentlock/rules](https://openagentlock.github.io/rules/) on top.
3. Optionally, a **private rules registry** with internal-to-your-org rules.

This page covers all three plus the YAML schema underneath them.

## Two switches: `mode` and rule actions

Two things determine whether a tool call is blocked:

1. **Top-level `mode`** at the root of your policy file: `monitor` or `enforce`. Without `mode: enforce`, every matched rule is downgraded to `allow` regardless of evaluator output.
2. **Per-rule action** (`on_hit`, `on_miss`).

`PATCH /v1/mode` toggles the daemon-level switch, which is the **outer** override. In `firewall` mode it escalates any policy-monitor match back to `deny`; in `monitor` mode it suppresses any policy `deny` to `allow`. Use it as the global kill switch — per-rule `mode: monitor` remains the right tool for staging individual rules during rollout.

## The community rules registry — start here

The [openagentlock/rules](https://github.com/openagentlock/rules) registry hosts ready-to-install gates the community has tested in the wild. Browse the catalog at <https://openagentlock.github.io/rules/>, copy the install one-liner, and paste:

```bash
# Upstream is auto-registered on first sync.
agentlock rules sync

# Search the catalog by name, tag, or description.
agentlock rules search exfil
agentlock rules search bash

# Install — the rule's gate block is POSTed to the daemon's
# /v1/policy/gates/yaml endpoint and lands in the live policy with a
# fresh hash. Existing sessions stay pinned to the old hash until they
# reload, so installs never invalidate in-flight work.
agentlock rules install exfil.curl-with-env
agentlock rules install rogue.secret-read

# Remove later — by gate id, the same /v1/policy/gates/{id} DELETE
# handler the dashboard uses.
agentlock rules uninstall exfil.curl-with-env
```

`agentlock rules` is wired through to the same daemon endpoint the [local web dashboard](dashboard.md) uses, so installs are immediately visible at `http://127.0.0.1:7879/rules`.

### Pin a private registry too

Most teams want a few internal-only rules alongside the upstream catalog. Any Git repo with the same `rules/<id>/rule.yaml` layout works:

```bash
# Tap your private registry. Multiple registries are merged at sync time.
agentlock rules add https://github.com/your-org/your-rules.git

# Confirm what's wired up.
agentlock rules sources

# Remove a registry (local-only — does not touch installed gates).
agentlock rules remove your-org-your-rules
```

If a rule id collides between two registries the CLI errors out and asks you to disambiguate with `<registry-id>:<rule-id>`. The same rule.yaml schema applies to both registries; the registry's own CI [validates against `schema/rule.schema.json`](https://github.com/openagentlock/rules/blob/main/schema/rule.schema.json) on every PR.

### Authoring new rules with an agent

When the catalog doesn't have what you need, the [openagentlock/skills](https://github.com/openagentlock/skills) toolkit ships agent skills (Claude Code, Cursor, Codex) that turn natural-language intent into a `rule.yaml` and run `agentlock rules install` to land it. See the `block-pattern` skill for the canonical "block this command shape" flow.

## The five built-in defaults

When the daemon boots, it loads `policies/default.yaml`, which ships these five gates in monitor mode. They are intentionally narrow — most operators leave them on and add registry rules on top.

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

The community registry has tighter / opinionated variants of several of these — e.g. `rogue.git-force-push` (only deny force-push to main / develop / release), `exfil.curl-with-env` (catch the `$ENV_VAR` exfil shape specifically), `rogue.eval-untrusted` (deny dynamic-eval shells). Install whichever match your threat model.

## Authoring rules from scratch

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

The full schema lives in [`api/openapi.yaml`](https://github.com/openagentlock/OpenAgentLock/blob/main/control-plane/api/openapi.yaml) under `components.schemas.Policy`. Community-rule authors should match the registry shape documented in [`schema/rule.schema.json`](https://github.com/openagentlock/rules/blob/main/schema/rule.schema.json). Minimal example:

```yaml
version: 1
mode: monitor
defaults:
  bash: allow
gates:
  - id: rogue.secret-read
    match:
      tool: Bash
      any_command_regex:
        - '(\.env(\b|[._-])|/\.ssh(/|\b)|/\.aws(/|\b)|credentials)'
    evaluate:
      - kind: always
        action: deny
```

The daemon's regex engine is Go RE2 — **no negative lookahead, no backreferences**. If you find yourself reaching for `(?!…)`, invert the match: write a positive regex for the dangerous shape rather than a negative regex around the safe one.

### Nudges

Each `evaluate[]` clause may carry an optional `nudge: <string>` hint. When the clause fires a `deny`, the harness shim splices the hint onto the reason it forwards to the model as `"<reason>\n\n→ Suggested: <nudge>"`. Use it to redirect the agent toward a safer command (e.g. `trash` instead of `rm`) or to point at the right [skill](https://github.com/openagentlock/skills) instead of leaving it to retry blindly.

```yaml
evaluate:
  - kind: always
    action: deny
    nudge: "use `trash <path>` (macOS) — recoverable from Trash"
```

Nudges only surface on `deny` verdicts; `allow`, monitor-suppressed, and non-matching paths drop the field. See the [openagentlock/rules](https://github.com/openagentlock/rules) registry for `safety.rm-suggest-trash` and `safety.secret-read-suggest-skill` as canonical examples.

## Enforcement vs monitor

- **Monitor** — every gate matches but the verdict is downgraded to `allow` for the harness. Use this on day one.
- **Enforce** — the verdict is honored. Switch on per-gate first if you want to ramp gradually; the schema permits a `mode` field on individual rules to override the global setting.
