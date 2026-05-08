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

# Or commit the rule to the current repo only. This writes the registry
# rule's gate block into .agentlock.yaml instead of the daemon policy.
agentlock rules install rogue.secret-read --repo

# Remove later — by gate id, the same /v1/policy/gates/{id} DELETE
# handler the dashboard uses.
agentlock rules uninstall exfil.curl-with-env
```

`agentlock rules` is wired through to the same daemon endpoint the [local web dashboard](dashboard.md) uses, so installs are immediately visible at `http://127.0.0.1:7879/rules`.

## Repo-local `.agentlock.yaml`

Repos can commit a root `.agentlock.yaml` for policy that applies only when a request `cwd` is inside that tree:

```yaml
version: 1
gates:
  - id: repo.block-prod-env
    match:
      tool: Bash
      any_command_regex:
        - 'cat\s+\.env\.production'
    evaluate:
      - kind: always
        action: deny
```

The daemon walks upward from `cwd` and uses the nearest `.agentlock.yaml`. Sibling repos are unaffected. Because cloned repos are not trusted, repo-local policy is additive by default: new deny-producing gates apply immediately, but disabled gates, same-id overrides, and `always: allow` content cannot weaken daemon policy without an operator approval flow. See [Per-Repo Policy](../architecture/per-repo-policy.md) for the full trust model and precedence chain.

## Group policy

Multi-user deployments can add `AGENTLOCK_HOME/group-policy.yaml` to layer group and personal gates over the daemon policy. Sessions may carry optional `user_id` and `groups` fields that determine which policy gates apply to each user. Today those fields can be supplied by the session API / CLI; directory-backed population belongs with the auth integration.

```yaml
version: 1
groups:
  compliance:
    gates:
      - id: group.secret-read
        match:
          tool: Bash
          command_regex: '^cat secret'
        evaluate:
          - kind: always
            action: deny
users:
  alice:
    groups: [compliance]
```

Across daemon, registry, group, user, and repo layers, deny-overrides is the default. A shared gate id may opt into `precedence: priority` plus `priority: <number>` when an operator wants highest-priority-wins for that id. Ledger entries include `policy_trace` so the dashboard can show which layers allowed or denied a call. See [Group Policy](../architecture/group-policy.md).

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

## First-boot baseline policy

When the daemon boots without `AGENTLOCK_POLICY` pointing at a custom file, it loads the **baseline policy embedded into the binary** at build time (source: `control-plane/internal/policy/baseline.yaml`). The baseline ships in `enforce` mode with thirteen gates so a fresh install has real protection without an `agentlock rules install` step.

| Gate | Severity | What it blocks |
|---|---|---|
| `rogue.destructive-bash` | high | `rm -rf /`, `DROP TABLE`, `dd if=…of=/dev/sd*`, `mkfs.*` |
| `supply-chain.installer-curl-bash` | high | `curl … \| bash`, `eval $(curl …)`, write-then-run installers, language-runtime pipes |
| `rogue.eval-untrusted` | high | `python -c 'exec(…)'`, `node -e 'eval(…)'`, `sh -c "$(curl …)"` |
| `rogue.reverse-shell` | critical | `bash -i >& /dev/tcp/…`, `nc -e`, socat exec, language socket+shell one-liners |
| `rogue.security-disable` | critical | `iptables -F`, `setenforce 0`, `csrutil disable`, `history -c`, CloudTrail/GuardDuty stop |
| `rogue.permission-loosening` | high | `chmod 777`, `chmod +s`, recursive `chown` of `/etc` `/usr` `/root` |
| `rogue.k8s-destructive` | critical | `kubectl delete ns`, `kubectl delete pv`, `helm uninstall`, `kubeadm reset` |
| `rogue.git-force-push` | high | `git push --force` to `main`/`master`/`develop`/`release/*` |
| `rogue.secret-read` | high | reads of `.env`, `.aws/credentials`, `.ssh/id_*`, kubeconfig, `.gnupg/*` |
| `exfil.cloud-cred-read` | critical | reads of gcloud / Azure / Docker / Terraform state / SA keys / Snowflake / Databricks creds |
| `rogue.system-auth-write` | critical | writes to `/etc/sudoers`, `/etc/passwd`, `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`, etc. (Write/Edit/MultiEdit + shell `tee`/redirect arms) |
| `rogue.shell-rc-write` | high | writes/appends to `~/.bashrc`, `~/.zshrc`, `~/.profile`, `/etc/profile.d/*` (persistence via shell init) |
| `rogue.cron-persistence` | high | `crontab -`, `systemd-run --on-calendar`, `at`, writes to `/etc/cron.d/*` and `/var/spool/cron/*` |

### Cross-harness coverage

Each harness sends a different tool-name string on the wire. Each gate's `match:` block uses `any_of` arms covering every shape:

- `tool: Bash` — Claude Code, Codex CLI
- `tool: Shell` — Cursor `preToolUse` + the synthetic `Shell` injected for `beforeShellExecution`
- `tool_prefix: mcp_` — Claude Desktop (MCP names use double-underscore `mcp__`) AND Gemini CLI (single-underscore `mcp_`); the single-underscore prefix is a strict superset of the double, so one arm catches both wire shapes
- `tool: Write` / `tool: Edit` / `tool: MultiEdit` — Claude Code's three file-edit primitives, plus `tool: Write` for Cursor (write/edit gates only)

| Harness | Shell coverage | File-read coverage | File-write coverage | Notes |
|---|---|---|---|---|
| Claude Code | ✅ full (`Bash`) | ✅ full (`Read`) | ✅ full (`Write`/`Edit`/`MultiEdit`) | |
| Codex CLI | ✅ reliable (`Bash`) | ❌ no `Read` tool — file reads do not fire `PreToolUse` per OpenAI Codex docs | ⚠️ `apply_patch` fires inconsistently per OpenAI codex#20204 | |
| Cursor | ✅ full (`Shell` arm) | ✅ full (`Read`) | ✅ full (`Write`) | |
| Claude Desktop | ✅ via MCP shell-exec servers | ✅ via MCP filesystem servers | ✅ via MCP filesystem write servers | Desktop is mcp-proxy-only — coverage requires the user to wire an MCP server for the relevant capability |
| Gemini CLI | ✅ via MCP shell-exec servers | ✅ via MCP filesystem servers | ✅ via MCP filesystem write servers | Native `run_shell_command` / `write_file` / `read_file` / `replace` bypass AgentLock today; tracked as a follow-up. Until native Gemini hooks land, baseline rules cover Gemini only when the workflow uses an MCP server |

### Layering registry rules on top

The baseline is intentionally tight — high-confidence, irreversible shapes only. The community catalog at <https://openagentlock.github.io/rules/> ships broader coverage (network egress allowlists, package typosquat, persistence shapes, etc.):

```bash
agentlock rules install rogue.net-egress            # block unknown-host curl/wget shapes
agentlock rules install supply-chain.npm-untrusted  # block installs from URL/git/tarball
agentlock rules install supply-chain.pip-untrusted  # same for pip / poetry / uv
agentlock rules install exfil.curl-with-env         # catch $ENV_VAR exfil shapes
agentlock rules install rogue.launchd-persistence   # macOS launchd-plist persistence
```

Pin a private registry alongside the upstream for org-internal rules — see the section above.

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
