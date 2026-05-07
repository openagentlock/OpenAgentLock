# Group Policy

OpenAgentLock supports a filesystem-backed group-policy bundle at `AGENTLOCK_HOME/group-policy.yaml`. The daemon combines that bundle with the session's optional `user_id` and `groups` fields to evaluate policy per session.

## Goals

Organizations need policy layers that are broader than one repo but narrower than the daemon's global policy. A compliance group may deny secret reads for everyone, while a red-team group may carry carefully reviewed allow rules. The evaluator must make these conflicts predictable and auditable.

## Identity Source

The current slice accepts identity on the session object:

```json
{
  "user_id": "alice",
  "groups": ["default", "red-team"]
}
```

This is intentionally a carrier, not the final identity source. OAL-21 owns OIDC/LDAP/group-claim resolution. Once that lands, the auth layer should populate the same session fields from trusted identity claims. Admin overrides can keep writing the same group-policy bundle.

## Schema

`AGENTLOCK_HOME/group-policy.yaml` is described by `control-plane/api/group-policy.schema.json`:

```yaml
version: 1
groups:
  default:
    gates:
      - id: group.default.secret-read
        match:
          tool: Bash
          command_regex: '^cat secret'
        evaluate:
          - kind: always
            action: deny

  red-team:
    inherits: [default]
    gates:
      - id: shared.net
        precedence: priority
        priority: 20
        match:
          tool: Bash
          command_regex: '^curl '
        evaluate:
          - kind: always
            action: allow

users:
  alice:
    groups: [red-team]
    gates:
      - id: user.alice.local-deny
        match:
          tool: Bash
          command_regex: '^open-prod-console'
        evaluate:
          - kind: always
            action: deny
```

Group and user `gates` use the same gate schema as daemon policy and `openagentlock/rules` gate blocks. If `source` is omitted, the daemon stamps `group:<name>` or `user:<id>`.

## Layering

Evaluation order is:

1. Daemon built-in or `AGENTLOCK_POLICY`
2. Registry-installed gates, carried in the daemon policy with `source: registry:<id>`
3. Group policies, one layer per resolved group
4. Personal user overlay
5. Repo-local `.agentlock.yaml` from OAL-72

Within a single layer, the existing policy behavior applies: first matching gate wins.

Across layers, the default is deny-overrides. The daemon evaluates every layer that contributes a verdict. If any contributing layer denies, the final verdict is deny. This means personal allow rules cannot bypass group denies by default.

For multiple top-level groups, the daemon iterates `session.groups` in the exact order provided. For each group it appends that group's resolved ancestry from root to child, then the group itself, while skipping duplicates so each resolved group appears once. Example: if `session.groups` is `[compliance, red-team]` and `red-team` inherits `default`, the resolved group layer order is `compliance`, `default`, `red-team`.

## Priority Conflicts

Operators can opt a shared gate id into priority-based resolution:

```yaml
id: shared.net
precedence: priority
priority: 20
```

When multiple layers match the same `id` and those gates use `precedence: priority`, the highest `priority` match is kept for that id before deny-overrides runs. This is deliberately explicit so allow-direction exceptions cannot happen by accident.

### Priority Resolution Details

`first matching gate wins` applies only within a single layer. If two gates in the same layer share an id and both declare `precedence: priority`, only the first matching gate in that layer contributes a verdict.

Across layers, `precedence: priority` compares the numeric `priority` field only when competing matches for the same id declare `precedence: priority`. If any matching gate for that id does not opt in, priority-based resolution is skipped for that non-priority match and standard deny-overrides still applies. This keeps allow-direction exceptions explicit and local to the shared id that opted into priority handling.

## Inheritance

Groups are parallel by default. A group inherits only when it declares `inherits: [...]`. Parents are evaluated before the child. Cycles are ignored after the first visit to avoid infinite inheritance.

## Conflict Reporting

Ledger entries include `policy_trace`, a compact list of contributing layer decisions:

```json
[
  {"layer":"group:compliance","rule_id":"shared.secret","verdict":"deny"},
  {"layer":"user:alice","rule_id":"user.secret-allow","verdict":"allow"}
]
```

The dashboard event detail renders this chain so an operator can see both the winning deny and the losing allow.

## Storage And Performance

This slice reads `group-policy.yaml` on demand from `AGENTLOCK_HOME`. The intended cache key is `(user_id, group_set, group_policy_hash, live_policy_hash, repo_policy_hash)`. A later cache should invalidate on group-policy mtime/size changes and on live policy swaps.

## Out Of Scope

- OIDC/LDAP group claim resolution: OAL-21.
- Dashboard editor for group policies: dashboard epic.
- Private registry management for org policy bundles.
