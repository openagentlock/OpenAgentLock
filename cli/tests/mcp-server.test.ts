// `agentlock mcp-server` JSON-RPC contract tests.
//
// Spawn the CLI as a subprocess (matching how Claude Desktop launches
// it), feed newline-delimited JSON-RPC, and check the responses.
//
// Run: cd cli && bun test tests/mcp-server.test.ts

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { join } from "node:path";

const CLI_ENTRY = join(import.meta.dir, "..", "src", "index.ts");

interface Reply {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: any;
  error?: { code: number; message: string };
}

// runMcp spawns `bun src/index.ts mcp-server`, sends each request as a
// newline-delimited JSON line, and returns the parsed replies in order.
// Closes stdin after the last request so the process exits.
async function runMcp(
  requests: Array<Record<string, unknown>>,
  daemonUrl?: string,
): Promise<Reply[]> {
  const env: Record<string, string> = { ...(process.env as Record<string, string>) };
  if (daemonUrl) env.AGENTLOCK_DAEMON_URL = daemonUrl;

  const child = spawn("bun", [CLI_ENTRY, "mcp-server"], {
    stdio: ["pipe", "pipe", "pipe"],
    env,
  });

  const stdoutChunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => stdoutChunks.push(c));

  for (const req of requests) {
    child.stdin.write(JSON.stringify(req) + "\n");
  }
  child.stdin.end();

  await new Promise<void>((resolve) => child.once("close", () => resolve()));

  const out = Buffer.concat(stdoutChunks).toString("utf8");
  const replies: Reply[] = [];
  for (const line of out.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    replies.push(JSON.parse(trimmed));
  }
  return replies;
}

let daemonServer: ReturnType<typeof Bun.serve> | undefined;
let daemonUrl: string;

beforeEach(() => {
  // Mock daemon for tools/call to hit. Each test starts a fresh server
  // so route handlers don't leak between cases.
  daemonServer = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/v1/health") {
        return Response.json({ status: "ok" });
      }
      if (url.pathname === "/v1/ledger/tail") {
        return Response.json({
          entries: [
            { seq: 1, verdict: "allow", tool_name: "Bash" },
            { seq: 2, verdict: "deny", tool_name: "Write" },
          ],
        });
      }
      return new Response("not found", { status: 404 });
    },
  });
  daemonUrl = `http://127.0.0.1:${daemonServer.port}`;
});

afterEach(() => {
  daemonServer?.stop();
});

describe("mcp-server", () => {
  test("initialize returns protocolVersion + tool capability", async () => {
    const [reply] = await runMcp([
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    ]);
    expect(reply).toBeDefined();
    expect(reply!.id).toBe(1);
    expect(reply!.result?.serverInfo?.name).toBe("agentlock");
    expect(reply!.result?.capabilities?.tools).toBeDefined();
  });

  test("tools/list returns the read-only observability tools", async () => {
    const replies = await runMcp([
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    ]);
    const list = replies.find((r) => r.id === 2);
    expect(list).toBeDefined();
    const names = (list!.result.tools as Array<{ name: string }>).map((t) => t.name);
    expect(names).toContain("agentlock_status");
    expect(names).toContain("agentlock_recent_decisions");
  });

  test("tools/call agentlock_status hits the daemon /v1/health", async () => {
    const replies = await runMcp(
      [
        { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
        {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "agentlock_status", arguments: {} },
        },
      ],
      daemonUrl,
    );
    const call = replies.find((r) => r.id === 2);
    expect(call).toBeDefined();
    const text = (call!.result.content as Array<{ text: string }>)[0]!.text;
    expect(text).toContain("reachable");
    expect(text).toContain("status=ok");
  });

  test("tools/call agentlock_status fails-soft when daemon is down", async () => {
    // Point at a port nothing is listening on.
    const replies = await runMcp(
      [
        { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
        {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "agentlock_status", arguments: {} },
        },
      ],
      "http://127.0.0.1:1", // port 1 is reserved; refused
    );
    const call = replies.find((r) => r.id === 2);
    expect(call).toBeDefined();
    // Must not return a JSON-RPC error — Claude reads tool errors as
    // model-visible failures. Surface the daemon-down state as text.
    expect(call!.error).toBeUndefined();
    const text = (call!.result.content as Array<{ text: string }>)[0]!.text;
    expect(text).toContain("daemon unreachable");
  });

  test("unknown tool returns -32602 invalid params", async () => {
    const replies = await runMcp([
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "agentlock_unknown" },
      },
    ]);
    const call = replies.find((r) => r.id === 2);
    expect(call?.error?.code).toBe(-32602);
  });

  test("unknown method returns -32601 method not found", async () => {
    const replies = await runMcp([
      { jsonrpc: "2.0", id: 1, method: "completely/made/up", params: {} },
    ]);
    const reply = replies[0];
    expect(reply?.error?.code).toBe(-32601);
  });
});
