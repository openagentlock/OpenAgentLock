// Wire-contract tests for the CLI's install client. Stands up a small
// mock control-plane via Bun.serve that speaks the same JSON shapes the
// real Go daemon does, and drives apiClient.{createUnattestedSession,
// installPlan, installApply, installUninstall} through every code path
// the CLI hits.
//
// Why this matters: the CLI and the Go control-plane share a JSON API
// but live in separate languages. Without a contract test here, a Go-
// side rename or shape change breaks `agentlock install` silently.
//
// These tests do NOT stand up a real daemon. They're fast (<100ms) and
// run on every `just cli-test`.

import { afterEach, describe, expect, test } from "bun:test";
import {
  apiClient,
  type ApiClient,
  type InstallPlanRequest,
} from "../src/util/api.ts";

interface RecordedRequest {
  method: string;
  path: string;
  body: unknown;
}

interface MockConfig {
  unattested?: {
    status?: number;
    body?: unknown;
  };
  plan?: {
    status?: number;
    body?: unknown;
  };
  apply?: {
    status?: number;
    body?: unknown;
  };
  uninstall?: {
    status?: number;
    body?: unknown;
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function startMockDaemon(
  config: MockConfig,
  recorded: RecordedRequest[],
): { server: ReturnType<typeof Bun.serve>; url: string } {
  const server = Bun.serve({
    port: 0, // OS-assigned — cheaper than racing for a fixed port.
    async fetch(req) {
      const url = new URL(req.url);
      const path = url.pathname;
      const body =
        req.method === "POST" ||
        req.method === "PATCH" ||
        req.method === "DELETE"
          ? await req.json().catch(() => null)
          : null;
      recorded.push({ method: req.method, path, body });

      if (path === "/v1/health") {
        return jsonResponse(200, { status: "ok" });
      }
      if (path === "/v1/sessions/unattested") {
        const cfg = config.unattested ?? {};
        return jsonResponse(
          cfg.status ?? 201,
          cfg.body ?? {
            id: "01KMOCK-SESSION",
            signer: "none",
            started_at: "2026-04-24T00:00:00Z",
            expires_at: "2026-04-25T00:00:00Z",
            banner: "UNATTESTED — LEDGER NOT SIGNED",
          },
        );
      }
      if (path === "/v1/install/plan") {
        const cfg = config.plan ?? {};
        return jsonResponse(
          cfg.status ?? 200,
          cfg.body ?? {
            session_id: "01KMOCK-SESSION",
            operations: [
              {
                op: "write",
                path: "/tmp/mock/.claude/settings.json",
                content: "{}",
                reason: "wire Claude Code hooks",
              },
            ],
            skipped: [],
            applied: false,
          },
        );
      }
      if (path === "/v1/install/apply") {
        const cfg = config.apply ?? {};
        return jsonResponse(
          cfg.status ?? 200,
          cfg.body ?? {
            session_id: "01KMOCK-SESSION",
            applied: true,
            operations: [
              {
                op: "write",
                path: "/tmp/mock/.claude/settings.json",
                reason: "wired Claude Code hooks",
                backup_path: "",
              },
            ],
            manifest_path: "/tmp/mock/install-manifests/01KMOCK-SESSION.json",
            skipped: [],
          },
        );
      }
      if (path === "/v1/install/uninstall") {
        const cfg = config.uninstall ?? {};
        return jsonResponse(
          cfg.status ?? 200,
          cfg.body ?? {
            session_id: "01KMOCK-SESSION",
            uninstalled: true,
            operations: [
              {
                op: "strip",
                path: "/tmp/mock/.claude/settings.json",
                entries_removed: 2,
              },
            ],
            failures: 0,
          },
        );
      }
      return new Response("not found", { status: 404 });
    },
  });
  return { server, url: `http://127.0.0.1:${server.port}` };
}

let server: ReturnType<typeof Bun.serve> | null = null;
let client: ApiClient;
let recorded: RecordedRequest[];

function withMock(config: MockConfig = {}): ApiClient {
  recorded = [];
  const started = startMockDaemon(config, recorded);
  server = started.server;
  return apiClient(started.url);
}

afterEach(() => {
  if (server) {
    server.stop(true);
    server = null;
  }
});

describe("apiClient.createUnattestedSession", () => {
  test("returns the parsed session on 201", async () => {
    client = withMock();
    const s = await client.createUnattestedSession();
    expect(s.id).toBe("01KMOCK-SESSION");
    expect(s.signer).toBe("none");
    expect(s.banner).toContain("UNATTESTED");
    expect(recorded.at(-1)?.path).toBe("/v1/sessions/unattested");
    expect(recorded.at(-1)?.method).toBe("POST");
  });

  test("throws with server body on non-201", async () => {
    client = withMock({
      unattested: {
        status: 403,
        body: { error: "unattested_disabled", detail: "flag required" },
      },
    });
    let caught: Error | null = null;
    try {
      await client.createUnattestedSession();
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).not.toBeNull();
    expect(caught!.message).toContain("sessions.unattested");
    expect(caught!.message).toContain("403");
    expect(caught!.message).toContain("unattested_disabled");
  });
});

const planReq: InstallPlanRequest = {
  session_id: "01KMOCK-SESSION",
  harnesses: ["claude-code"],
  daemon_url: "http://127.0.0.1:7878",
  config_dir_override: "/tmp/mock/.claude",
};

describe("apiClient.installPlan", () => {
  test("returns operations on success", async () => {
    client = withMock();
    const plan = await client.installPlan(planReq);
    expect(plan.applied).toBe(false);
    expect(plan.operations).toHaveLength(1);
    expect(plan.operations[0].op).toBe("write");
  });

  test("propagates 400 errors with body", async () => {
    client = withMock({
      plan: {
        status: 400,
        body: { error: "invalid_request", detail: "daemon_url required" },
      },
    });
    await expect(client.installPlan(planReq)).rejects.toThrow(/install.plan.*400/);
  });
});

describe("apiClient.installApply", () => {
  test("returns applied=true and manifest_path on success", async () => {
    client = withMock();
    const apply = await client.installApply(planReq);
    expect(apply.applied).toBe(true);
    expect(apply.manifest_path).toContain("install-manifests");
    expect(apply.skipped).toEqual([]);
  });

  test("surfaces 403 error body verbatim", async () => {
    client = withMock({
      apply: {
        status: 403,
        body: { error: "forbidden", detail: "session lacks signer" },
      },
    });
    let caught: Error | null = null;
    try {
      await client.installApply(planReq);
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).not.toBeNull();
    expect(caught!.message).toContain("forbidden");
    expect(caught!.message).toContain("403");
  });
});

describe("apiClient.installUninstall", () => {
  test("returns uninstalled=true on 200", async () => {
    client = withMock();
    const r = await client.installUninstall({ session_id: "01KMOCK-SESSION" });
    expect(r.uninstalled).toBe(true);
    expect(r.failures).toBe(0);
    expect(r.operations[0].entries_removed).toBe(2);
  });

  test("accepts 207 Multi-Status (partial failure) as non-error", async () => {
    client = withMock({
      uninstall: {
        status: 207,
        body: {
          session_id: "01KMOCK-SESSION",
          uninstalled: false,
          operations: [
            {
              op: "strip",
              path: "/tmp/mock/.claude/settings.json",
              entries_removed: 1,
              error: "",
            },
            {
              op: "strip",
              path: "/tmp/mock/.cursor/settings.json",
              entries_removed: 0,
              error: "read /tmp/mock/.cursor/settings.json: permission denied",
            },
          ],
          failures: 1,
        },
      },
    });
    const r = await client.installUninstall({ session_id: "01KMOCK-SESSION" });
    expect(r.failures).toBe(1);
    expect(r.uninstalled).toBe(false);
    expect(r.operations[1].error).toContain("permission denied");
  });

  test("throws on 404 manifest not found", async () => {
    client = withMock({
      uninstall: {
        status: 404,
        body: { error: "manifest_not_found", detail: "bad-session-id" },
      },
    });
    await expect(
      client.installUninstall({ session_id: "bad-session-id" }),
    ).rejects.toThrow(/404/);
  });
});
