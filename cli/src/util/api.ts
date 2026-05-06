// Thin HTTP client for the OpenAgentLock control-plane. Loopback only;
// no auth header in v1 (host is the trust boundary — see docs/reference/api.md).

export interface ApiClient {
  baseUrl: string;
  token: string | null;
  setToken(token: string | null): void;
  ledgerTailUrl(): string;
  // Tail the ledger SSE stream. Uses fetch + ReadableStream so it works
  // under runtimes that don't expose a global EventSource (e.g. Bun).
  // Auto-reconnects with a 2s backoff until the returned cancel is called.
  tailLedger(opts: {
    onEntry: (entry: unknown) => void;
    onStatus?: (status: "connecting" | "open" | "closed") => void;
  }): () => void;
  authMode(): Promise<AuthModeResponse>;
  authLogin(username: string, password: string): Promise<AuthLoginResponse>;
  authBootstrap(username: string, password: string): Promise<AuthBootstrapResponse>;
  authLogout(): Promise<void>;
  health(): Promise<HealthResponse>;
  createSession(req: SessionStartRequest): Promise<SessionResponse>;
  createUnattestedSession(): Promise<UnattestedSessionResponse>;
  endSession(id: string): Promise<void>;
  rotateSession(id: string, req: SessionStartRequest): Promise<SessionResponse>;
  checkGate(req: GateCheckRequest): Promise<GateCheckResponse>;
  ledgerRoot(): Promise<LedgerRootResponse>;
  ledgerVerify(): Promise<LedgerVerifyResponse>;
  installCapabilities(): Promise<InstallCapabilitiesResponse>;
  installPlan(req: InstallPlanRequest): Promise<InstallPlanResponse>;
  installApply(req: InstallPlanRequest): Promise<InstallApplyResponse>;
  installUninstall(req: {
    session_id: string;
    existing_files?: Record<string, string>;
  }): Promise<InstallUninstallResponse>;
  installUninstallHarnesses(req: {
    session_id: string;
    harnesses: string[];
    config_dir_override?: string;
    harness_config_dirs?: Record<string, string>;
    existing_files?: Record<string, string>;
  }): Promise<InstallUninstallResponse>;
  listSessions(): Promise<SessionsListResponse>;
  getMode(): Promise<ModeResponse>;
  patchMode(mode: "firewall" | "monitor" | ""): Promise<ModeResponse>;
  policyView(): Promise<PolicyViewResponse>;
  installGateYAML(yaml: string, replace?: boolean): Promise<InstallGateYAMLResponse>;
  addGate(req: AddGateRequest): Promise<InstallGateYAMLResponse>;
  patchGate(id: string, req: PatchGateRequest): Promise<InstallGateYAMLResponse>;
  deleteGate(id: string): Promise<DeleteGateResponse>;
  ledgerInsights(window?: InsightWindow, top?: number): Promise<LedgerInsightsResponse>;
}

export type InsightWindow = "1h" | "24h" | "7d" | "all";

export interface AddGateRequest {
  id: string;
  tool?: string;
  tool_prefix?: string;
  any_command_regex?: string[];
  any_path_regex?: string[];
  any_url_regex?: string[];
  path_glob?: string;
  action: "deny" | "allow";
  mode?: string;
}

export interface PatchGateRequest {
  disabled?: boolean;
  any_command_regex?: string[];
  mode?: string;
}

export interface InsightCount {
  key: string;
  count: number;
}

export interface InsightBucket {
  ts: string;
  allow: number;
  deny: number;
}

export interface LedgerInsightsResponse {
  window: InsightWindow;
  now: string;
  bucket_seconds: number;
  total: number;
  by_verdict: Record<string, number>;
  by_source: Record<string, number>;
  top_rules_deny: InsightCount[];
  top_tools_deny: InsightCount[];
  buckets: InsightBucket[];
}

export interface InstallGateYAMLResponse {
  hash: string;
  gates: number;
  id: string;
  needs_reload: boolean;
}

export interface DeleteGateResponse {
  hash: string;
  gates: number;
  needs_reload: boolean;
}

export interface SessionSummary {
  id: string;
  harness: string;
  signer: string;
  policy_hash: string;
  active: boolean;
  needs_reload: boolean;
  started_at?: string;
  ended_at?: string;
}

export interface SessionsListResponse {
  live_policy_hash: string;
  sessions: SessionSummary[];
}

export interface ModeResponse {
  mode: "firewall" | "monitor";
  env?: string;
  runtime_override?: string;
}

export interface PolicyGateView {
  id: string;
  mode?: string;
  disabled?: boolean;
  tool?: string;
  tool_prefix?: string;
  any_command_regex?: string[];
  evaluators?: string[];
}

export interface PolicyViewResponse {
  hash: string;
  policy_mode: string;
  daemon_mode: string;
  gates: PolicyGateView[];
}

export interface AuthModeResponse {
  mode: "none" | "password" | "oidc" | "ldap";
  users_configured: boolean;
  users_count: number;
}

export interface AuthLoginResponse {
  token: string;
  expires_at: number;
  username: string;
}

export interface AuthBootstrapResponse {
  username: string;
  hint: string;
}

export interface UnattestedSessionResponse {
  id: string;
  signer: string;
  started_at: string;
  expires_at: string;
  banner?: string;
}

export interface InstallPlanRequest {
  session_id: string;
  harnesses: string[];
  daemon_url: string;
  config_dir_override?: string;
  // Optional override for the binary Codex's command-hooks should spawn.
  // Defaults to "agentlock" (PATH lookup at hook time). Pass an absolute
  // path for dev / CI runs where PATH may not include the build output.
  agentlock_binary?: string;
  // Pre-resolved host paths for each harness's config dir. When set, the
  // daemon uses these instead of probing its own $HOME — this is what
  // makes the install flow honest under Docker, where the daemon's HOME
  // is /home/nonroot but the user expects writes under their real home.
  harness_config_dirs?: Record<string, string>;
  // Existing host file contents the daemon needs to merge against when
  // computing ops. Keys are absolute paths; missing keys mean "file does
  // not exist." The CLI populates this for ~/.claude/settings.json,
  // ~/.codex/hooks.json, ~/.codex/config.toml, and ~/.cursor/hooks.json
  // so the daemon never has to read host paths itself.
  existing_files?: Record<string, string>;
}

export interface InstallCapabilitiesResponse {
  unattested_allowed: boolean;
  container: boolean;
}

export interface InstallFileOp {
  op: string;
  path: string;
  content?: string;
  reason?: string;
  backup_path?: string;
}

export interface InstallPlanResponse {
  session_id: string;
  operations: InstallFileOp[];
  skipped: string[];
  warnings?: string[];
  applied: boolean;
  apply_note?: string;
}

export interface InstallApplyResponse {
  session_id: string;
  applied: boolean;
  operations: InstallFileOp[];
  manifest_path: string;
  skipped: string[];
  warnings?: string[];
}

export interface InstallUninstallOp {
  op: string;
  path: string;
  entries_removed: number;
  // Post-strip file contents the CLI should write back to `path`.
  // Empty when the file had no agentlock entries (the CLI then leaves
  // the file untouched).
  content?: string;
  error?: string;
}

export interface InstallUninstallResponse {
  session_id: string;
  uninstalled: boolean;
  operations: InstallUninstallOp[];
  failures: number;
}

export interface LedgerRootResponse {
  root: string;
  seq: number;
  count: number;
  computed_at: string;
}

export interface LedgerVerifyResponse {
  ok: boolean;
  root?: string;
  count: number;
  first_bad_at?: number;
  reason?: string;
}

export interface GateCheckRequest {
  session_id: string;
  source: string;
  tool: string;
  input: Record<string, unknown>;
  cwd?: string;
  meta?: Record<string, unknown>;
}

export interface GateCheckResponse {
  verdict: "allow" | "deny";
  rule_id: string;
  reason: string;
  ledger_seq: number;
  monitor?: boolean;
}

export interface HealthResponse {
  status: string;
}

export interface SessionStartRequest {
  policy_hash: string;
  session_pubkey: string;
  signer: string;
  signer_pubkey: string;
  attestation: string;
}

export interface SessionResponse {
  id: string;
  started_at: string;
  expires_at: string;
  policy_hash: string;
  session_pubkey: string;
  signer: string;
  signer_pubkey: string;
}

export function apiClient(baseUrl?: string, initialToken?: string | null): ApiClient {
  const url =
    baseUrl ??
    process.env.AGENTLOCK_CONTROL_PLANE_URL ??
    "http://127.0.0.1:7878";

  const tok = initialToken ?? process.env.AGENTLOCK_TOKEN ?? null;

  let cachedCapabilities: InstallCapabilitiesResponse | null = null;

  // authHeaders returns { Authorization: Bearer <tok> } when the client
  // has a token, otherwise {}. Used internally by every gated request.
  function authHeaders(): Record<string, string> {
    return client.token ? { Authorization: `Bearer ${client.token}` } : {};
  }

  const client: ApiClient = {
    baseUrl: url,
    token: tok,

    setToken(token: string | null): void {
      client.token = token;
    },

    ledgerTailUrl(): string {
      // EventSource can't attach custom headers. When auth is on, the
      // token rides as a query param. The daemon accepts both.
      const base = `${url}/v1/ledger/tail`;
      return client.token ? `${base}?token=${encodeURIComponent(client.token)}` : base;
    },

    tailLedger(opts): () => void {
      const ctrl = new AbortController();
      void (async () => {
        while (!ctrl.signal.aborted) {
          opts.onStatus?.("connecting");
          try {
            const res = await fetch(client.ledgerTailUrl(), {
              headers: { Accept: "text/event-stream" },
              signal: ctrl.signal,
            });
            if (!res.ok || !res.body) {
              opts.onStatus?.("closed");
            } else {
              opts.onStatus?.("open");
              await readSSE(res.body, opts.onEntry, ctrl.signal);
              opts.onStatus?.("closed");
            }
          } catch {
            if (ctrl.signal.aborted) return;
            opts.onStatus?.("closed");
          }
          if (ctrl.signal.aborted) return;
          await sleepUnlessAborted(2000, ctrl.signal);
        }
      })();
      return () => ctrl.abort();
    },

    async authMode(): Promise<AuthModeResponse> {
      const res = await fetch(`${url}/v1/auth/mode`);
      if (!res.ok) throw new Error(`auth.mode: ${res.status} ${res.statusText}`);
      return (await res.json()) as AuthModeResponse;
    },

    async authLogin(username: string, password: string): Promise<AuthLoginResponse> {
      const res = await fetch(`${url}/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`auth.login: ${res.status} ${res.statusText}: ${body}`);
      }
      const out = (await res.json()) as AuthLoginResponse;
      client.token = out.token;
      return out;
    },

    async authBootstrap(
      username: string,
      password: string,
    ): Promise<AuthBootstrapResponse> {
      const res = await fetch(`${url}/v1/auth/bootstrap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (res.status !== 201) {
        const body = await res.text();
        throw new Error(`auth.bootstrap: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as AuthBootstrapResponse;
    },

    async authLogout(): Promise<void> {
      if (!client.token) return;
      await fetch(`${url}/v1/auth/logout`, {
        method: "POST",
        headers: authHeaders(),
      }).catch(() => {});
      client.token = null;
    },

    async health(): Promise<HealthResponse> {
      const res = await fetch(`${url}/v1/health`);
      if (!res.ok) {
        throw new Error(`health: ${res.status} ${res.statusText}`);
      }
      return (await res.json()) as HealthResponse;
    },

    async createSession(req: SessionStartRequest): Promise<SessionResponse> {
      const res = await fetch(`${url}/v1/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (res.status !== 201) {
        const body = await res.text();
        throw new Error(`sessions.create: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as SessionResponse;
    },

    async checkGate(req: GateCheckRequest): Promise<GateCheckResponse> {
      const res = await fetch(`${url}/v1/gates/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (res.status !== 200) {
        const body = await res.text();
        throw new Error(`gates.check: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as GateCheckResponse;
    },

    async endSession(id: string): Promise<void> {
      const res = await fetch(`${url}/v1/sessions/${encodeURIComponent(id)}/end`, {
        method: "POST",
        headers: authHeaders(),
      });
      if (res.status !== 204) {
        const body = await res.text();
        throw new Error(`sessions.end: ${res.status} ${res.statusText}: ${body}`);
      }
    },

    async rotateSession(id: string, req: SessionStartRequest): Promise<SessionResponse> {
      const res = await fetch(`${url}/v1/sessions/${encodeURIComponent(id)}/rotate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (res.status !== 200) {
        const body = await res.text();
        throw new Error(`sessions.rotate: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as SessionResponse;
    },

    async ledgerRoot(): Promise<LedgerRootResponse> {
      const res = await fetch(`${url}/v1/ledger/root`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`ledger.root: ${res.status} ${res.statusText}`);
      return (await res.json()) as LedgerRootResponse;
    },

    async ledgerVerify(): Promise<LedgerVerifyResponse> {
      const res = await fetch(`${url}/v1/ledger/verify`, {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`ledger.verify: ${res.status} ${res.statusText}`);
      return (await res.json()) as LedgerVerifyResponse;
    },

    async createUnattestedSession(): Promise<UnattestedSessionResponse> {
      const res = await fetch(`${url}/v1/sessions/unattested`, {
        method: "POST",
        headers: authHeaders(),
      });
      if (res.status !== 201) {
        const body = await res.text();
        throw new Error(
          `sessions.unattested: ${res.status} ${res.statusText}: ${body}`,
        );
      }
      return (await res.json()) as UnattestedSessionResponse;
    },

    async installCapabilities(): Promise<InstallCapabilitiesResponse> {
      // Cache on the client so plan + apply don't re-fetch. Capabilities
      // can only change with a daemon restart — caching for the lifetime
      // of a CLI invocation is safe.
      if (cachedCapabilities) return cachedCapabilities;
      const res = await fetch(`${url}/v1/install/capabilities`);
      if (!res.ok) {
        throw new Error(
          `install.capabilities: ${res.status} ${res.statusText}`,
        );
      }
      cachedCapabilities = (await res.json()) as InstallCapabilitiesResponse;
      return cachedCapabilities;
    },

    async installPlan(req: InstallPlanRequest): Promise<InstallPlanResponse> {
      const res = await fetch(`${url}/v1/install/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`install.plan: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as InstallPlanResponse;
    },

    async installApply(req: InstallPlanRequest): Promise<InstallApplyResponse> {
      const res = await fetch(`${url}/v1/install/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`install.apply: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as InstallApplyResponse;
    },

    async installUninstall(req: {
      session_id: string;
      existing_files?: Record<string, string>;
    }): Promise<InstallUninstallResponse> {
      const res = await fetch(`${url}/v1/install/uninstall`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (!res.ok && res.status !== 207) {
        const body = await res.text();
        throw new Error(
          `install.uninstall: ${res.status} ${res.statusText}: ${body}`,
        );
      }
      return (await res.json()) as InstallUninstallResponse;
    },

    async installUninstallHarnesses(req: {
      session_id: string;
      harnesses: string[];
      config_dir_override?: string;
      harness_config_dirs?: Record<string, string>;
      existing_files?: Record<string, string>;
    }): Promise<InstallUninstallResponse> {
      const res = await fetch(`${url}/v1/install/uninstall-harnesses`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      // 207 (multi-status) is a partial-success the daemon emits when
      // some entries failed to strip; surface the body either way.
      if (!res.ok && res.status !== 207) {
        const body = await res.text();
        throw new Error(
          `install.uninstall_harnesses: ${res.status} ${res.statusText}: ${body}`,
        );
      }
      return (await res.json()) as InstallUninstallResponse;
    },

    async listSessions(): Promise<SessionsListResponse> {
      const res = await fetch(`${url}/v1/sessions`, { headers: authHeaders() });
      if (!res.ok) {
        throw new Error(`sessions.list: ${res.status} ${res.statusText}`);
      }
      return (await res.json()) as SessionsListResponse;
    },

    async getMode(): Promise<ModeResponse> {
      const res = await fetch(`${url}/v1/mode`, { headers: authHeaders() });
      if (!res.ok) {
        throw new Error(`mode.get: ${res.status} ${res.statusText}`);
      }
      return (await res.json()) as ModeResponse;
    },

    async patchMode(mode: "firewall" | "monitor" | ""): Promise<ModeResponse> {
      const res = await fetch(`${url}/v1/mode`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ mode }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`mode.patch: ${res.status} ${res.statusText}: ${body}`);
      }
      return (await res.json()) as ModeResponse;
    },

    async policyView(): Promise<PolicyViewResponse> {
      const res = await fetch(`${url}/v1/policy/view`, { headers: authHeaders() });
      if (!res.ok) {
        throw new Error(`policy.view: ${res.status} ${res.statusText}`);
      }
      return (await res.json()) as PolicyViewResponse;
    },

    async installGateYAML(yaml: string, replace?: boolean): Promise<InstallGateYAMLResponse> {
      const res = await fetch(`${url}/v1/policy/gates/yaml`, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders() },
        body: JSON.stringify({ yaml, replace: !!replace }),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`policy.install_gate_yaml: ${res.status} ${res.statusText} ${body}`);
      }
      return (await res.json()) as InstallGateYAMLResponse;
    },

    async deleteGate(id: string): Promise<DeleteGateResponse> {
      const res = await fetch(`${url}/v1/policy/gates/${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`policy.delete_gate: ${res.status} ${res.statusText} ${body}`);
      }
      return (await res.json()) as DeleteGateResponse;
    },

    async addGate(req: AddGateRequest): Promise<InstallGateYAMLResponse> {
      const res = await fetch(`${url}/v1/policy/gates`, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`policy.add_gate: ${res.status} ${res.statusText} ${body}`);
      }
      return (await res.json()) as InstallGateYAMLResponse;
    },

    async patchGate(id: string, req: PatchGateRequest): Promise<InstallGateYAMLResponse> {
      const res = await fetch(`${url}/v1/policy/gates/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", ...authHeaders() },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`policy.patch_gate: ${res.status} ${res.statusText} ${body}`);
      }
      return (await res.json()) as InstallGateYAMLResponse;
    },

    async ledgerInsights(
      window: InsightWindow = "24h",
      top?: number,
    ): Promise<LedgerInsightsResponse> {
      const qs = new URLSearchParams({ window });
      if (top !== undefined) qs.set("top", String(top));
      const res = await fetch(`${url}/v1/ledger/insights?${qs}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`ledger.insights: ${res.status} ${res.statusText} ${body}`);
      }
      return (await res.json()) as LedgerInsightsResponse;
    },
  };

  return client;
}

// readSSE consumes a Server-Sent Events stream and invokes onEntry for
// each `data:` frame parsed as JSON. Comment frames (keepalives) and
// non-JSON payloads are skipped silently. Returns when the stream ends
// or the signal aborts.
async function readSSE(
  body: ReadableStream<Uint8Array>,
  onEntry: (entry: unknown) => void,
  signal: AbortSignal,
): Promise<void> {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    while (!signal.aborted) {
      const { value, done } = await reader.read();
      if (done) return;
      buf += dec.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const data = frame
          .split("\n")
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).replace(/^ /, ""))
          .join("\n");
        if (!data) continue;
        try {
          onEntry(JSON.parse(data));
        } catch {
          // skip malformed frame
        }
      }
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // best-effort
    }
  }
}

function sleepUnlessAborted(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        resolve();
      },
      { once: true },
    );
  });
}
