// E2E test for the `agentlock hook codex <event>` shim. Spawns a mock
// daemon over Bun.serve, runs the shim binary with stdin piped JSON,
// and asserts the shim exits 0 (allow) or 2 (deny) and forwards the
// payload verbatim to /v1/hooks/codex/<event>.

import { afterEach, describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { join } from "node:path";

interface MockExpect {
  status?: number;
  body?: unknown;
}

interface RecordedRequest {
  path: string;
  body: unknown;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function startMockDaemon(
  expects: Record<string, MockExpect>,
  recorded: RecordedRequest[],
): { server: ReturnType<typeof Bun.serve>; url: string } {
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      const body = req.method === "POST" ? await req.json().catch(() => null) : null;
      recorded.push({ path: url.pathname, body });
      const cfg = expects[url.pathname];
      if (cfg) {
        return jsonResponse(cfg.status ?? 200, cfg.body ?? { continue: true });
      }
      return new Response("not found", { status: 404 });
    },
  });
  return { server, url: `http://127.0.0.1:${server.port}` };
}

interface ShimResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runShim(
  args: string[],
  payload: string,
  daemonUrl: string,
  extraEnv: Record<string, string> = {},
  harness = "codex",
): Promise<ShimResult> {
  return new Promise((resolve, reject) => {
    const entry = join(import.meta.dir, "..", "src", "index.ts");
    const proc = spawn("bun", ["run", entry, "hook", harness, ...args], {
      env: {
        ...process.env,
        AGENTLOCK_DAEMON_URL: daemonUrl,
        ...extraEnv,
      },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (c: Buffer) => {
      stdout += c.toString("utf8");
    });
    proc.stderr.on("data", (c: Buffer) => {
      stderr += c.toString("utf8");
    });
    proc.on("error", reject);
    proc.on("close", (code: number | null) => {
      resolve({ code, stdout, stderr });
    });
    proc.stdin.write(payload);
    proc.stdin.end();
  });
}

describe("hook codex-desktop shim", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  test("forwards to codex-desktop route", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/codex-desktop/pre-tool-use": {
          status: 200,
          body: {
            continue: true,
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "allow",
            },
          },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "desktop_sess_x",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "desktop_t_01",
      tool_input: { command: "ls" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url, {}, "codex-desktop");
    expect(r.code).toBe(0);
    expect(recorded).toHaveLength(1);
    expect(recorded[0].path).toBe("/v1/hooks/codex-desktop/pre-tool-use");
  });
});

describe("hook codex-auto shim", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  test("desktop environment routes to codex-desktop", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/codex-desktop/pre-tool-use": {
          status: 200,
          body: { continue: true },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "auto_desktop_sess",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "auto_desktop_t_01",
      tool_input: { command: "ls" },
    });
    const r = await runShim(
      ["pre-tool-use"],
      payload,
      m.url,
      { __CFBundleIdentifier: "com.openai.codex" },
      "codex-auto",
    );
    expect(r.code).toBe(0);
    expect(recorded[0].path).toBe("/v1/hooks/codex-desktop/pre-tool-use");
  });
});

describe("hook codex shim", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  test("allow → exit 0", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/codex/pre-tool-use": {
          status: 200,
          body: {
            continue: true,
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "allow",
            },
          },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "sess_x",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "t_01",
      tool_input: { command: "ls" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(0);
    expect(recorded).toHaveLength(1);
    expect(recorded[0].path).toBe("/v1/hooks/codex/pre-tool-use");
    expect(recorded[0].body).toMatchObject({ tool_name: "Bash" });
  });

  test("deny → exit 2 with reason on stderr", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/codex/pre-tool-use": {
          status: 200,
          body: {
            continue: false,
            stopReason: "matched rule rogue.destructive-bash (deny)",
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason: "matched rule rogue.destructive-bash (deny)",
            },
          },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "sess_y",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "t_02",
      tool_input: { command: "rm -rf /tmp/x" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("rogue.destructive-bash");
    // stdout carries the JSON for harnesses that prefer it.
    expect(r.stdout).toContain('"permissionDecision":"deny"');
  });

  test("deny with nudge → stderr carries the suggested-line", async () => {
    // Same forwarding contract as the claude-code shim: the daemon
    // builds "<reason>\n\n→ Suggested: <hint>" and the shim mirrors
    // that text onto stderr so Codex shows the hint to the model.
    const recorded: RecordedRequest[] = [];
    const concatenated =
      "matched rule safety.rm-suggest-trash (deny)\n\n→ Suggested: use trash instead";
    const m = startMockDaemon(
      {
        "/v1/hooks/codex/pre-tool-use": {
          status: 200,
          body: {
            continue: false,
            stopReason: concatenated,
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason: concatenated,
            },
          },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "sess_nudge",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "t_nudge",
      tool_input: { command: "rm -rf /tmp/x" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("→ Suggested: ");
    expect(r.stderr).toContain("use trash instead");
    expect(r.stderr).toContain("safety.rm-suggest-trash");
  });

  test("daemon unreachable → silent fail-open on every event", async () => {
    // Codex hides hook stderr on exit-0 and renders any non-zero exit
    // as a "(failed)" banner that looks like a real error. Neither is
    // an acceptable channel for a status nudge, so we stay completely
    // silent — empty stdout, empty stderr, exit 0.
    for (const event of ["session-start", "pre-tool-use", "post-tool-use", "stop"]) {
      const r = await runShim(
        [event],
        JSON.stringify({ session_id: "sess_q", hook_event_name: event }),
        "http://127.0.0.1:1",
      );
      expect(r.code).toBe(0);
      expect(r.stdout).toBe("");
      expect(r.stderr).toBe("");
    }
  });

  test("unknown event → exit 2 with usage", async () => {
    const r = await runShim(["bogus"], "", "http://127.0.0.1:1");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("usage");
  });
});
