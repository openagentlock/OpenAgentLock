# False Positive Reporting Design

Date: 2026-05-08

## Goal

Give users a fast, auditable way to recover from a false-positive policy match without weakening protection. A user should be able to start from a blocked or monitored ledger event, understand the rule that fired, replace that rule locally with a safer version, and optionally prepare a patch for the upstream `openagentlock/rules` registry.

This design keeps policy evaluation deterministic. LLM or skill-assisted rule writing happens outside the hook hot path and produces artifacts that the product validates before applying.

## Non-Goals

- Do not add an LLM dependency to the daemon or hook verdict path.
- Do not auto-open pull requests to `openagentlock/rules` in v1.
- Do not silently add broad allow exceptions around false positives.
- Do not disable a matched rule before a replacement rule validates and the user confirms.

## User Flow

The primary entrypoint is event detail, not a global report form.

In the web dashboard, a user opens a blocked or monitor-alert event detail and chooses `Report false positive`. In the TUI, a user opens the same event detail and chooses the false-positive action from the detail actions. The CLI exposes the same flow by sequence number for automation and terminal-first use.

The flow:

1. Build a redacted false-positive case bundle from the ledger event, matched rule, policy trace, input command/path/url, source harness, cwd when available, and hashes.
2. Show the event and old rule that fired.
3. Let the user draft a replacement rule manually, through `$EDITOR`, by pasting YAML, or by invoking an AgentLock skill that consumes the case bundle.
4. Validate the replacement rule against the original event and built-in regression examples.
5. Atomically apply the change: mark the old rule disabled and install the replacement rule.
6. Optionally prepare a rules-registry patch draft in an `openagentlock/rules` checkout.

The product must never leave the old rule disabled unless a replacement rule is installed in the same confirmed operation.

## Core Model

Introduce a shared false-positive case bundle. Web, TUI, CLI, and skills all use this bundle rather than inventing separate payloads.

The bundle contains:

- `schema_version`
- `created_at`
- `event.seq`, `source`, `tool`, `verdict`, `monitor_match`, `rule_id`, `tool_use_id`
- redacted input fields for command, path, URL, cwd, and relevant tool input
- `policy_trace`
- matched gate view, including source, mode, disabled state, recursive match schema, and evaluator summary
- hashes needed for audit correlation: payload hash, leaf hash, previous leaf
- redaction metadata describing which fields were changed
- optional raw event payload only when the user explicitly opts in

The daemon/API should expose deterministic bundle creation so the same event produces the same redacted report from every surface.

## Local Policy Change

False-positive resolution is not an allow override. It is a local replacement:

- The old matched gate stays present with `disabled: true`.
- Metadata records why it was disabled, including false-positive event seq, timestamp, replacement rule id, and a human-readable note.
- The replacement gate is installed into the selected target.

Target selection defaults to `auto`:

- If the event cwd is inside a git repository, suggest repo policy `.agentlock.yaml`.
- Otherwise, suggest daemon/user policy.

The user can override the target before apply.

Atomic apply must validate both resulting policies before writing:

- old gate disabled
- replacement gate present
- replacement YAML parses
- replacement rule does not match the original false-positive event as a deny
- resulting policy hash can be computed

If any validation fails, no policy file is changed.

## Web Dashboard

Event detail shows `Report false positive` only for events with a matched rule and a deny or monitor-alert verdict. It should not appear on post-tool child rows such as `ran` or `tool errored`.

The web flow uses a guided drawer or modal:

1. Event summary and original command/path/url.
2. Matched rule and source.
3. Replacement rule editor.
4. Test panel that runs the replacement against the original event and selected known-bad examples.
5. Apply confirmation.
6. Optional export for upstream patch drafting.

The UI should make it clear that applying will disable the old rule and install the replacement together.

## TUI Dashboard

The TUI mirrors the web flow inside event detail. The selected event detail shows a false-positive action only when the current entry has a matched deny or monitor-alert rule.

The TUI flow:

1. Open event detail.
2. Choose `Report false positive`.
3. Review the redacted case bundle and old rule.
4. Choose target: auto, repo, or user.
5. Open `$EDITOR` with a replacement gate YAML draft.
6. Validate.
7. Confirm atomic apply.
8. Optionally write a rules-registry patch draft.

Arrow keys and vim keys should work for navigation, matching the rest of the TUI.

## CLI

Add a scriptable command family:

```bash
agentlock false-positive <seq> --target auto|repo|user --out <dir> [--include-raw]
agentlock false-positive apply <case-dir>
agentlock false-positive rules-patch <case-dir> --rules-repo <path>
```

The first command creates the bundle and a replacement-rule draft directory. `apply` validates and performs the atomic local policy change. `rules-patch` writes a ready-to-edit patch draft into a rules repo checkout when available.

CLI output should clearly state whether raw event data was included and where the bundle was written.

## Skill Integration

Skills consume the case bundle and may produce:

- a replacement local gate
- a short explanation of why the old rule false-positive matched
- a rules-registry patch draft

The product should treat skill output as untrusted text until it passes deterministic validation. A skill can help author the YAML, but it cannot directly bypass validation or apply changes without the product flow.

## Upstream Patch Draft

When the target rule came from `registry:<id>`, the optional upstream flow can prepare changes in an `openagentlock/rules` checkout.

The draft should include:

- updated `rule.yaml`
- README note explaining the false positive and intended boundary
- test fixture proving the false-positive command is allowed
- test fixture proving the malicious pattern is still blocked
- redacted event report

The command does not auto-commit or open a PR in v1. If no rules repo checkout exists, write a portable report bundle that the user can attach to an issue or hand to a skill.

## API Surface

Add API endpoints behind the existing loopback/auth model:

- `GET /v1/false-positives/cases/{seq}`: build a redacted case bundle for a ledger event.
- `POST /v1/false-positives/validate`: validate a replacement gate against a case bundle.
- `POST /v1/false-positives/apply`: atomically disable the old gate and install the replacement.

The apply endpoint must require the caller to echo the current policy hash or matched gate fingerprint so stale UI state cannot overwrite newer policy edits.

## Error Handling

Expected failures:

- Event seq not found.
- Event has no matched rule.
- Event is not a deny or monitor-alert decision.
- Matched rule no longer exists in the live policy.
- Current policy hash differs from the bundle.
- Replacement YAML is invalid.
- Replacement still denies the original false-positive event.
- Target repo policy cannot be found or written.
- Rules repo checkout is missing or dirty.

Failures should be actionable and should not partially change policy state.

## Testing

Add tests for:

- deterministic redacted bundle shape
- secret/path redaction behavior
- no false-positive action for post-tool outcome rows
- disabled-gate round trip through policy CRUD
- atomic apply rollback on invalid replacement
- repo-vs-user target inference
- validation rejects a replacement that still denies the original event
- rules patch generation includes allow and deny fixtures
- web and TUI action visibility for deny, monitor alert, allow, and post-tool rows

No test should require an LLM provider.

## Open Decisions

No product-blocking decisions remain for v1. The implementation can pick exact keyboard shortcuts, modal copy, and file names while preserving the behavior above.
