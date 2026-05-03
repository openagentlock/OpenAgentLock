// E2E test for the `agentlock hook claude-code <event>` shim. Spawns a
// mock daemon over Bun.serve, runs the shim binary with stdin piped JSON,
// and asserts the shim exits 0 (allow) or 2 (deny) and forwards the
// payload verbatim to /v1/hooks/claude-code/<event>. The daemon-down
// path must be silent on stdout AND stderr — any text would either land
// in Claude's input stream or trigger a red harness banner. The visible
// "daemon offline" signal is owned out-of-band by the statusLine config
// the installer writes (see installStatusLineScript in commands/install).

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
    const proc = spawn("bun", ["run", entry, "hook", "claude-code", ...args], {
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

describe("hook claude-code shim", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  test("allow → exit 0", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/claude-code/pre-tool-use": {
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
    expect(recorded[0].path).toBe("/v1/hooks/claude-code/pre-tool-use");
    expect(recorded[0].body).toMatchObject({ tool_name: "Bash" });
  });

  test("deny → exit 2 with reason on stderr", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/claude-code/pre-tool-use": {
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
    expect(r.stdout).toContain('"permissionDecision":"deny"');
  });

  test("daemon unreachable → silent fail-open on every event", async () => {
    // Every event must produce empty stdout AND empty stderr with exit 0.
    // Anything else either pollutes the model's input stream or triggers
    // a red 'hook error' banner in Claude Code's UI.
    const home = mkdtempSync(join(tmpdir(), "agentlock-test-"));
    for (const event of ["session-start", "pre-tool-use", "post-tool-use", "stop"]) {
      const payload = JSON.stringify({
        session_id: "sess_z",
        hook_event_name: event,
      });
      const r = await runShim([event], payload, "http://127.0.0.1:1", {
        AGENTLOCK_HOME: home,
      });
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
