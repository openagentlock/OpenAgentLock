// Contract tests for the CLI's auth glue: authMode, authLogin,
// authBootstrap, authLogout, and the bearer-token injection that every
// gated call depends on. Mock daemon via Bun.serve as elsewhere.

import { afterEach, describe, expect, test } from "bun:test";
import { apiClient } from "../src/util/api.ts";

interface Rec {
  method: string;
  path: string;
  auth: string | null;
  body: unknown;
}

interface MockOpts {
  users?: number;
  loginStatus?: number;
  loginBody?: unknown;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function startMock(opts: MockOpts, recorded: Rec[]): { url: string; stop: () => void } {
  const validTokens = new Set<string>(["VALID-TOKEN"]);
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const u = new URL(req.url);
      const auth = req.headers.get("Authorization");
      const body =
        req.method === "POST" || req.method === "PATCH"
          ? await req.json().catch(() => null)
          : null;
      recorded.push({ method: req.method, path: u.pathname, auth, body });

      if (u.pathname === "/v1/health") return jsonResponse(200, { status: "ok" });
      if (u.pathname === "/v1/auth/mode") {
        return jsonResponse(200, {
          mode: "password",
          users_configured: (opts.users ?? 1) > 0,
          users_count: opts.users ?? 1,
        });
      }
      if (u.pathname === "/v1/auth/bootstrap") {
        if ((opts.users ?? 0) > 0) {
          return jsonResponse(409, { error: "already_bootstrapped" });
        }
        return jsonResponse(201, {
          username: (body as { username: string }).username,
          hint: "now POST /v1/auth/login",
        });
      }
      if (u.pathname === "/v1/auth/login") {
        if (opts.loginStatus && opts.loginStatus !== 200) {
          return jsonResponse(opts.loginStatus, opts.loginBody ?? { error: "bad_credentials" });
        }
        validTokens.add("VALID-TOKEN");
        return jsonResponse(200, {
          token: "VALID-TOKEN",
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          username: (body as { username: string }).username,
        });
      }
      if (u.pathname === "/v1/auth/logout") {
        const tok = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
        validTokens.delete(tok);
        return jsonResponse(200, { status: "ok" });
      }
      // Gated endpoint: require Bearer
      if (u.pathname === "/v1/sessions") {
        const tok = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
        if (!validTokens.has(tok)) {
          return jsonResponse(401, { error: "missing_bearer" });
        }
        return jsonResponse(200, {
          live_policy_hash: "sha256:abc",
          sessions: [],
        });
      }
      return jsonResponse(404, { error: "not_found" });
    },
  });
  return {
    url: `http://${server.hostname}:${server.port}`,
    stop: () => server.stop(true),
  };
}

describe("auth API contract", () => {
  let stopFn: (() => void) | null = null;
  afterEach(() => {
    if (stopFn) stopFn();
    stopFn = null;
  });

  test("authMode reports password + users_configured", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock({ users: 1 }, rec);
    stopFn = stop;
    const api = apiClient(url);
    const m = await api.authMode();
    expect(m.mode).toBe("password");
    expect(m.users_configured).toBe(true);
    expect(m.users_count).toBe(1);
  });

  test("authLogin stores token on client", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock({ users: 1 }, rec);
    stopFn = stop;
    const api = apiClient(url);
    expect(api.token).toBeNull();
    const r = await api.authLogin("admin", "password-at-least-ten");
    expect(r.token).toBe("VALID-TOKEN");
    expect(api.token).toBe("VALID-TOKEN");
  });

  test("gated calls send Bearer after login", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock({ users: 1 }, rec);
    stopFn = stop;
    const api = apiClient(url);
    await api.authLogin("admin", "password-at-least-ten");
    await api.listSessions();
    const sessionsCall = rec.find(
      (r) => r.path === "/v1/sessions" && r.method === "GET",
    );
    expect(sessionsCall?.auth).toBe("Bearer VALID-TOKEN");
  });

  test("gated call without a token fails with 401", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock({ users: 1 }, rec);
    stopFn = stop;
    const api = apiClient(url);
    await expect(api.listSessions()).rejects.toThrow(/401/);
  });

  test("authBootstrap accepts 201 and 409", async () => {
    // fresh daemon — no users
    const rec1: Rec[] = [];
    const { url: urlEmpty, stop: s1 } = startMock({ users: 0 }, rec1);
    const api1 = apiClient(urlEmpty);
    const r = await api1.authBootstrap("admin", "password-at-least-ten");
    expect(r.username).toBe("admin");
    s1();

    // existing user — expect a thrown 409
    const rec2: Rec[] = [];
    const { url: urlExists, stop: s2 } = startMock({ users: 1 }, rec2);
    stopFn = s2;
    const api2 = apiClient(urlExists);
    await expect(
      api2.authBootstrap("admin", "password-at-least-ten"),
    ).rejects.toThrow(/409/);
  });

  test("authLogout clears the stored token", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock({ users: 1 }, rec);
    stopFn = stop;
    const api = apiClient(url);
    await api.authLogin("admin", "password-at-least-ten");
    expect(api.token).toBe("VALID-TOKEN");
    await api.authLogout();
    expect(api.token).toBeNull();
  });

  test("initialToken constructor param populates the client bearer", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock({ users: 1 }, rec);
    stopFn = stop;
    const api = apiClient(url, "VALID-TOKEN");
    await api.listSessions();
    const sessionsCall = rec.find((r) => r.path === "/v1/sessions");
    expect(sessionsCall?.auth).toBe("Bearer VALID-TOKEN");
  });

  test("ledgerTailUrl stamps the token as a query param when set", () => {
    const api = apiClient("http://127.0.0.1:4242", "TOK");
    expect(api.ledgerTailUrl()).toBe(
      "http://127.0.0.1:4242/v1/ledger/tail?token=TOK",
    );
  });

  test("login with bad credentials throws", async () => {
    const rec: Rec[] = [];
    const { url, stop } = startMock(
      { users: 1, loginStatus: 401, loginBody: { error: "bad_credentials" } },
      rec,
    );
    stopFn = stop;
    const api = apiClient(url);
    await expect(api.authLogin("admin", "wrong")).rejects.toThrow(/401/);
    expect(api.token).toBeNull();
  });
});
