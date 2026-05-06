# Per-Repo Policy

OpenAgentLock supports a repo-local `.agentlock.yaml` at the repository root. The daemon finds the nearest enclosing `.agentlock.yaml` by walking up from the request `cwd`, then overlays its gates onto the live daemon policy for that request only.

## Goals

Different repositories carry different risk. A production monorepo can commit stricter rules for secrets, deploy tooling, or cloud mutation while a sandbox repo stays lighter. Because the policy file is committed with code, reviewers see changes to automation safety in the same pull request as the code those rules govern.

## File Name

The canonical file name is `.agentlock.yaml`.

Rejected aliases for now:

- `.agentlock`: ambiguous file type.
- `.agentlockrc.yaml`: reads like user-local config, not repository policy.
- `agentlock.yaml`: too visible for a repo-root control file and inconsistent with similar hidden repo metadata files.

## Schema

The file reuses the daemon policy gate shape and the `openagentlock/rules` `rule.yaml` `gate:` block shape.

```yaml
version: 1
extends:
  - rogue.destructive-bash
gates:
  - id: repo.block-secret-print
    match:
      tool: Bash
      any_command_regex:
        - 'cat\s+secrets\.txt'
    evaluate:
      - kind: always
        action: deny
```

`gates` are inline daemon gates. `extends` is a manifest of registry rule ids a repo wants; the CLI can materialize a registry rule into `.agentlock.yaml` with `agentlock rules install <id> --repo`. Version pinning for registry rules is deferred until the registry publishes immutable rule revisions. Until then, registry rules can change under the same id; operators should monitor registry diffs, prefer inline `gates` for critical security controls, and use CI or manual review alerts to catch unexpected rule changes. Once immutable revisions exist, repo manifests should pin to those revisions.

## Trust Model

A cloned repository is not trusted. A malicious repo-local policy must not be able to weaken the daemon policy.

The default behavior is:

- Restrictive additions take effect immediately. A new deny-producing gate can only block more actions.
- Permissive changes are ignored unless an operator has approved the exact file hash.
- Same-id overrides from repo policy are ignored by default, because replacing a daemon gate can weaken it even when the replacement still contains a deny.
- Disabled gates and `always: allow` gates are treated as permissive and ignored.

The approval model is TOFU on file content hash:

1. The daemon computes a content hash for `.agentlock.yaml`.
2. If the file contains permissive content, the daemon requires an operator approval tied to `(path, hash)`.
3. Edits change the hash and require approval again.
4. Approved permissive overrides are scoped to that file path and hash.

The current implementation ships the safe default path: restrictive additive gates apply; permissive repo content is ignored. Operator approval UI/API is the next slice.

## Composition

Policy layers are evaluated from broadest to narrowest:

1. Daemon built-in or `AGENTLOCK_POLICY`
2. User policy
3. Group policy from OAL-73
4. Repo-local `.agentlock.yaml`

Most restrictive wins. In practice that means a deny from any layer blocks the call. Repo-local same-id gates do not replace daemon gates unless their content hash is approved for permissive override handling.

Dashboard policy views include rule source metadata (`daemon`, `registry:<id>`, or `per-repo:<path>`) so operators can tell where a rule came from. Conflict reporting should group same-id gates by source and explain which layer won.

## Cwd Resolution

Every gate check and harness hook that carries `cwd` uses the same resolver:

1. Convert `cwd` to an absolute path.
2. If it is a file, start at its parent.
3. Check for `.agentlock.yaml`.
4. Walk parent directories until filesystem root.
5. Use the nearest file only.

The resolver fails closed for repo policy loading errors by ignoring unreadable or invalid repo files rather than weakening daemon policy. A later cache should key by directory device/inode and invalidate on `(path, mtime, size)` to avoid repeated stat walks.

## Sandbox Repos

Public or newly cloned repos are treated as untrusted. Restrictive gates can apply immediately. Any file content that attempts to allow, disable, replace, or downgrade enforcement requires hash-pinned approval before it can affect decisions.

## Hooks Without Cwd

If a harness event has no `cwd`, repo-local policy is not applied. The daemon uses the session-pinned live policy only. This avoids guessing from process state or tool paths.

## Example

```yaml
version: 1
gates:
  - id: repo.no-prod-env-cat
    match:
      tool: Bash
      any_command_regex:
        - 'cat\s+\.env\.production'
    evaluate:
      - kind: always
        action: deny
        nudge: "Read the documented config shape instead of printing production secrets."
```
