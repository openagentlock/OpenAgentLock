// E2E test for the `agentlock hook cursor <event>` shim. Spawns a mock
// daemon over Bun.serve, runs the shim binary with stdin piped JSON,
// and asserts the shim emits Cursor's expected
// {permission, agent_message?} envelope on stdout, plus the right exit
// code. Mirrors the claude-code/codex test shape.

import { afterEach, describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
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
): Promise<ShimResult> {
  return new Promise((resolve, reject) => {
    const entry = join(import.meta.dir, "..", "src", "index.ts");
    const proc = spawn("bun", ["run", entry, "hook", "cursor", ...args], {
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

describe("hook cursor shim", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  test("allow → exit 0 with permission:allow", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/cursor/pre-tool-use": {
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
      conversation_id: "conv_x",
      hook_event_name: "preToolUse",
      tool_name: "Bash",
      tool_input: { command: "ls" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ permission: "allow" });
    expect(recorded[0].path).toBe("/v1/hooks/cursor/pre-tool-use");
  });

  test("deny → exit 2 with reason on stderr and stdout", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/cursor/pre-tool-use": {
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
      conversation_id: "conv_y",
      hook_event_name: "preToolUse",
      tool_name: "Bash",
      tool_input: { command: "rm -rf /tmp/x" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("rogue.destructive-bash");
    expect(r.stdout).toContain('"permission":"deny"');
    expect(r.stdout).toContain("rogue.destructive-bash");
  });

  test("daemon unreachable → silent fail-open with plain allow envelope on every event", async () => {
    // Cursor has no UI surface outside the model's input stream that we
    // can write to (no statusLine, no safe agent_message). On a transport
    // failure we just emit a plain {permission:allow} so Cursor doesn't
    // surface a hook error and the user's tool call goes through.
    const home = mkdtempSync(join(tmpdir(), "agentlock-test-"));
    for (const event of ["session-start", "pre-tool-use", "post-tool-use"]) {
      const r = await runShim(
        [event],
        JSON.stringify({ conversation_id: "conv_x", hook_event_name: event }),
        "http://127.0.0.1:1",
        { AGENTLOCK_HOME: home },
      );
      expect(r.code).toBe(0);
      expect(r.stderr).toBe("");
      expect(JSON.parse(r.stdout)).toEqual({ permission: "allow" });
    }
  });

  test("unknown event → exit 2 with usage", async () => {
    const r = await runShim(["bogus"], "", "http://127.0.0.1:1");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("usage");
  });
});
