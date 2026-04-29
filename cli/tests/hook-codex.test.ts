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
): Promise<ShimResult> {
  return new Promise((resolve, reject) => {
    const entry = join(import.meta.dir, "..", "src", "index.ts");
    const proc = spawn("bun", ["run", entry, "hook", "codex", ...args], {
      env: {
        ...process.env,
        AGENTLOCK_DAEMON_URL: daemonUrl,
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

  test("daemon unreachable → fail-open exit 0", async () => {
    const payload = JSON.stringify({
      session_id: "sess_z",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "t_03",
      tool_input: { command: "ls" },
    });
    // Use a port we know nothing's listening on.
    const r = await runShim(["pre-tool-use"], payload, "http://127.0.0.1:1");
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("daemon unreachable");
  });

  test("unknown event → exit 2 with usage", async () => {
    const r = await runShim(["bogus"], "", "http://127.0.0.1:1");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("usage");
  });
});
