// E2E test for the `agentlock hook gemini <event>` shim. Spawns a mock
// daemon over Bun.serve, runs the shim binary with stdin piped JSON,
// and asserts the shim exits 0 (allow) or 2 (deny) and forwards the
// payload verbatim to /v1/hooks/gemini/<event>.
//
// Gemini-specific: response shape is flat {decision, reason} (NOT
// Claude/Codex's nested hookSpecificOutput.permissionDecision). On
// allow we MUST keep stdout empty — Gemini parses stdout as JSON.

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
): Promise<ShimResult> {
  return new Promise((resolve, reject) => {
    const entry = join(import.meta.dir, "..", "src", "index.ts");
    const proc = spawn("bun", ["run", entry, "hook", "gemini", ...args], {
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

describe("hook gemini shim", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  test("allow → exit 0 with EMPTY stdout (gemini parses stdout as JSON)", async () => {
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/gemini/pre-tool-use": {
          status: 200,
          body: { continue: true, decision: "allow" },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "sess_x",
      hook_event_name: "BeforeTool",
      tool_name: "run_shell_command",
      tool_input: { command: "ls" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(0);
    // CRITICAL: empty stdout on allow. Gemini will choke if we emit
    // anything that doesn't parse as a hook envelope.
    expect(r.stdout).toBe("");
    expect(recorded).toHaveLength(1);
    expect(recorded[0].path).toBe("/v1/hooks/gemini/pre-tool-use");
    expect(recorded[0].body).toMatchObject({ tool_name: "run_shell_command" });
  });

  test("deny → exit 2 with reason on stderr and JSON envelope on stdout", async () => {
    const recorded: RecordedRequest[] = [];
    const reason = "matched rule rogue.destructive-bash (deny)";
    const m = startMockDaemon(
      {
        "/v1/hooks/gemini/pre-tool-use": {
          status: 200,
          body: {
            continue: false,
            stopReason: reason,
            decision: "deny",
            reason,
          },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "sess_y",
      hook_event_name: "BeforeTool",
      tool_name: "run_shell_command",
      tool_input: { command: "rm -rf /tmp/x" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("rogue.destructive-bash");
    // Gemini reads stdout JSON OR exit code — emit both.
    expect(r.stdout).toContain('"decision":"deny"');
    expect(r.stdout).toContain('"reason"');
  });

  test("deny with nudge → stderr carries the suggested-line", async () => {
    // Daemon builds "<reason>\n\n→ Suggested: <hint>" and the shim
    // mirrors that text onto stderr so Gemini renders the hint to the
    // model.
    const recorded: RecordedRequest[] = [];
    const concatenated =
      "matched rule safety.rm-suggest-trash (deny)\n\n→ Suggested: use trash instead";
    const m = startMockDaemon(
      {
        "/v1/hooks/gemini/pre-tool-use": {
          status: 200,
          body: {
            continue: false,
            stopReason: concatenated,
            decision: "deny",
            reason: concatenated,
          },
        },
      },
      recorded,
    );
    server = m.server;

    const payload = JSON.stringify({
      session_id: "sess_nudge",
      hook_event_name: "BeforeTool",
      tool_name: "run_shell_command",
      tool_input: { command: "rm -rf /tmp/x" },
    });
    const r = await runShim(["pre-tool-use"], payload, m.url);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("→ Suggested: ");
    expect(r.stderr).toContain("use trash instead");
    expect(r.stderr).toContain("safety.rm-suggest-trash");
  });

  test("daemon unreachable → silent fail-open on every event", async () => {
    // Gemini parses stdout as JSON, so any stdout text (including an
    // "offline" notice) would error the harness. Stay completely
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

  test("observability event with continue:true (no decision field) → exit 0 silent", async () => {
    // SessionStart / PostToolUse / Stop come back as plain
    // {continue: true} with no `decision`. Treat as allow.
    const recorded: RecordedRequest[] = [];
    const m = startMockDaemon(
      {
        "/v1/hooks/gemini/post-tool-use": {
          status: 200,
          body: { continue: true },
        },
      },
      recorded,
    );
    server = m.server;

    const r = await runShim(
      ["post-tool-use"],
      JSON.stringify({ session_id: "sess_o", hook_event_name: "AfterTool" }),
      m.url,
    );
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("");
  });

  test("unknown event → exit 2 with usage", async () => {
    const r = await runShim(["bogus"], "", "http://127.0.0.1:1");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("usage");
  });
});
