// Wire-contract tests for the dashboard TUI's read-mostly surface.
// Exercises the new endpoints agentlock dashboard relies on:
//   GET  /v1/mode          → ModeResponse
//   PATCH /v1/mode          → ModeResponse
//   GET  /v1/sessions       → SessionsListResponse
//   GET  /v1/policy/view    → PolicyViewResponse
//   ledgerTailUrl()         → URL helper
//
// Mock daemon is Bun.serve on an OS-assigned port, same pattern as
// install-api.test.ts. Tests are <100ms, hermetic, go into cli-test.

import { afterEach, describe, expect, test } from "bun:test";
import { apiClient } from "../src/util/api.ts";

interface Recorded {
  method: string;
  path: string;
  body: unknown;
}

interface MockOpts {
  mode?: { status?: number; body?: unknown };
  patch?: { status?: number; body?: unknown; echo?: boolean };
  sessions?: { status?: number; body?: unknown };
  policy?: { status?: number; body?: unknown };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function startMock(opts: MockOpts, recorded: Recorded[]): { url: string; stop: () => Promise<void> } {
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const u = new URL(req.url);
      const body =
        req.method === "POST" || req.method === "PATCH"
          ? await req.json().catch(() => null)
          : null;
      recorded.push({ method: req.method, path: u.pathname, body });
      if (u.pathname === "/v1/health") return json(200, { status: "ok" });
      if (u.pathname === "/v1/mode" && req.method === "GET") {
        const c = opts.mode ?? {};
        return json(
          c.status ?? 200,
          c.body ?? {
            mode: "firewall",
            env: "",
            runtime_override: "",
          },
        );
      }
      if (u.pathname === "/v1/mode" && req.method === "PATCH") {
        const c = opts.patch ?? {};
        if (c.echo) {
          const desired = (body as { mode?: string })?.mode ?? "firewall";
          return json(200, {
            mode: desired === "" ? "firewall" : desired,
            env: "",
            runtime_override: desired,
          });
        }
        return json(c.status ?? 200, c.body ?? { mode: "monitor" });
      }
      if (u.pathname === "/v1/sessions" && req.method === "GET") {
        const c = opts.sessions ?? {};
        return json(
          c.status ?? 200,
          c.body ?? {
            live_policy_hash: "sha256:abc123",
            sessions: [
              {
                id: "SESS-1",
                harness: "claude-code",
                signer: "none",
                policy_hash: "sha256:abc123",
                active: true,
                needs_reload: false,
              },
            ],
          },
        );
      }
      if (u.pathname === "/v1/policy/view" && req.method === "GET") {
        const c = opts.policy ?? {};
        return json(
          c.status ?? 200,
          c.body ?? {
            hash: "sha256:abc123",
            policy_mode: "enforce",
            daemon_mode: "firewall",
            gates: [
              {
                id: "rogue.destructive-bash",
                mode: "enforce",
                tool: "Bash",
                any_command_regex: ["^rm -rf"],
                evaluators: ["*policy.RegexEvaluator"],
              },
            ],
          },
        );
      }
      return json(404, { error: "not_found", path: u.pathname });
    },
  });
  return {
    url: `http://${server.hostname}:${server.port}`,
    async stop() {
      server.stop(true);
    },
  };
}

describe("dashboard API contract", () => {
  let stopFn: (() => Promise<void>) | null = null;
  afterEach(async () => {
    if (stopFn) await stopFn();
    stopFn = null;
  });

  test("getMode returns the expected shape", async () => {
    const recorded: Recorded[] = [];
    const { url, stop } = startMock({}, recorded);
    stopFn = stop;
    const api = apiClient(url);
    const m = await api.getMode();
    expect(m.mode).toBe("firewall");
    expect(m.env).toBe("");
    expect(m.runtime_override).toBe("");
    expect(recorded.at(-1)?.method).toBe("GET");
    expect(recorded.at(-1)?.path).toBe("/v1/mode");
  });

  test("patchMode sends the JSON body and surfaces daemon's echo", async () => {
    const recorded: Recorded[] = [];
    const { url, stop } = startMock({ patch: { echo: true } }, recorded);
    stopFn = stop;
    const api = apiClient(url);
    const m = await api.patchMode("monitor");
    expect(m.mode).toBe("monitor");
    expect(m.runtime_override).toBe("monitor");
    const last = recorded.at(-1);
    expect(last?.method).toBe("PATCH");
    expect(last?.body).toEqual({ mode: "monitor" });
  });

  test("patchMode with empty string clears the override", async () => {
    const recorded: Recorded[] = [];
    const { url, stop } = startMock({ patch: { echo: true } }, recorded);
    stopFn = stop;
    const api = apiClient(url);
    const m = await api.patchMode("");
    expect(m.mode).toBe("firewall");
    expect(m.runtime_override).toBe("");
  });

  test("patchMode throws with body prefix on 400", async () => {
    const recorded: Recorded[] = [];
    const { url, stop } = startMock(
      { patch: { status: 400, body: { error: "invalid_mode" } } },
      recorded,
    );
    stopFn = stop;
    const api = apiClient(url);
    await expect(api.patchMode("panic" as "monitor")).rejects.toThrow(/invalid_mode/);
  });

  test("listSessions projects the fields TUI rows need", async () => {
    const { url, stop } = startMock({}, []);
    stopFn = stop;
    const api = apiClient(url);
    const r = await api.listSessions();
    expect(r.live_policy_hash).toBe("sha256:abc123");
    expect(r.sessions).toHaveLength(1);
    const s = r.sessions[0]!;
    expect(s.id).toBe("SESS-1");
    expect(s.harness).toBe("claude-code");
    expect(s.active).toBe(true);
    expect(s.needs_reload).toBe(false);
  });

  test("policyView returns hash + gates array", async () => {
    const { url, stop } = startMock({}, []);
    stopFn = stop;
    const api = apiClient(url);
    const p = await api.policyView();
    expect(p.hash).toBe("sha256:abc123");
    expect(p.policy_mode).toBe("enforce");
    expect(p.gates).toHaveLength(1);
    expect(p.gates[0]!.id).toBe("rogue.destructive-bash");
  });

  test("ledgerTailUrl points at /v1/ledger/tail under the base URL", () => {
    const api = apiClient("http://127.0.0.1:4242");
    expect(api.ledgerTailUrl()).toBe("http://127.0.0.1:4242/v1/ledger/tail");
  });

  test("getMode surfaces 5xx as an Error for the TUI to catch", async () => {
    const recorded: Recorded[] = [];
    const { url, stop } = startMock(
      { mode: { status: 500, body: { error: "boom" } } },
      recorded,
    );
    stopFn = stop;
    const api = apiClient(url);
    await expect(api.getMode()).rejects.toThrow(/500/);
  });
});
