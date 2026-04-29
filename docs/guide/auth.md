# Authentication

The control plane runs an HTTP API. Today that API is bound to `127.0.0.1` by default, so the host is the trust boundary; the CLI does not send an auth header. Multi-user / on-prem deployments will need stronger auth, and the daemon already has the mode-toggle plumbing for it.

## Modes

| Mode | Status | What |
|---|---|---|
| `password` | <span class="md-status-pill shipped">Shipped</span> | Local password against the daemon. The dashboard uses this. |
| `oidc` | <span class="md-status-pill not-yet">Not yet implemented</span> | OIDC bearer tokens. Stubbed; returns a hint when you try to use it. |
| `ldap` | <span class="md-status-pill not-yet">Not yet implemented</span> | LDAP bind. Stubbed. |

The daemon's auth mode is set at startup via `AGENTLOCK_AUTH_MODE`. The default is `password` for local-only deployments.

## Local password

```bash
agentlock login
# Username:
# Password:
```

The CLI stores the resulting token in your OS keychain (when the OS-keychain signer ships) or, today, in a session file under `${AGENTLOCK_HOME}/session.json`.

## OIDC (planned)

When OIDC ships, the daemon will validate JWTs via JWKS. The brainstormed shape:

```yaml
auth:
  mode: oidc
  oidc:
    issuer: https://accounts.google.com
    audience: openagentlock-control-plane
    jwks_uri: https://www.googleapis.com/oauth2/v3/certs
    require_email_domain: yourcompany.com
```

Compatible with Google Workspace, Okta, Azure AD, Keycloak, Authentik, and any other OIDC-compliant IdP.

## LDAP (planned)

LDAP / Active Directory will support directory-driven group membership for [RBAC rules](#rbac-planned).

## RBAC (planned)

A role grants a set of capabilities to a subject, an email pattern, or a group claim. Policy rules can require a role:

```yaml
gates:
  - id: rogue.destructive-bash
    when:
      command_regex: 'rm -rf|DROP TABLE'
    on_hit: deny
    require_role: senior-engineer
```

The control plane already accepts a `role` claim in the session bundle; enforcement on the policy side is the missing piece.

## What you should do today

For single-developer local installs: the default is fine. The daemon binds to loopback, the host is your trust boundary.

For team / on-prem: stand it up locally first, then track the OIDC / RBAC roadmap. Both surfaces are designed in `api/openapi.yaml` already; only the implementations are pending.
