// `agentlock mcp-proxy` end-to-end contract.
//
// Spawn the CLI with a tiny fake MCP child + a mock daemon, feed JSON-
// RPC frames, assert the proxy honors policy and passes through.
//
// Run: cd cli && bun test tests/mcp-proxy.test.ts

import { afterEach, describe, expect, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";

import { parseProxyArgs } from "../src/commands/mcp-proxy.ts";

const CLI_ENTRY = join(import.meta.dir, "..", "src", "index.ts");

// Minimal fake MCP server: reads JSON-RPC requests on stdin, echoes
// each one back as a canned response. Used as the proxy's child.
const FAKE_CHILD = `
let buf = '';
process.stdin.on('data', (c) => {
  buf += c.toString('utf8');
  let nl;
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === 'initialize') {
      process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result:{protocolVersion:'2024-11-05',capabilities:{tools:{}},serverInfo:{name:'fake',version:'0.0.1'}}}) + '\\n');
    } else if (msg.method === 'tools/list') {
      process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result:{tools:[{name:'echo',description:'',inputSchema:{type:'object'}}]}}) + '\\n');
    } else if (msg.method === 'tools/call') {
      process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result:{content:[{type:'text',text:'CHILD_RAN:'+JSON.stringify(msg.params)}]}}) + '\\n');
    }
  }
});
`;

interface ProxyHandle {
  child: ChildProcess;
  stdoutLines: string[];
  daemonHits: Array<{ path: string; body: any }>;
  daemonStop: () => void;
}

function startProxy(opts: {
  serverName: string;
  daemonBehavior: "allow" | "deny" | "down";
  denyReason?: string;
}): ProxyHandle {
  const daemonHits: Array<{ path: string; body: any }> = [];
  let daemonUrl = "http://127.0.0.1:1"; // unreachable port for "down"
  let stop: () => void = () => {};
  if (opts.daemonBehavior !== "down") {
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const url = new URL(req.url);
        const body = await req.json().catch(() => ({}));
        daemonHits.push({ path: url.pathname, body });
        if (url.pathname === "/v1/hooks/claude-desktop/pre-tool-use") {
          if (opts.daemonBehavior === "deny") {
            return Response.json({
              continue: false,
              stopReason: opts.denyReason ?? "denied by test policy",
              hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason: opts.denyReason ?? "denied by test policy",
              },
            });
          }
          return Response.json({
            continue: true,
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "allow",
            },
          });
        }
        if (url.pathname === "/v1/hooks/claude-desktop/post-tool-use") {
          return Response.json({ continue: true });
        }
        return new Response("not found", { status: 404 });
      },
    });
    daemonUrl = `http://127.0.0.1:${server.port}`;
    stop = () => server.stop();
  }

  const env = { ...(process.env as Record<string, string>), AGENTLOCK_DAEMON_URL: daemonUrl };
  const child = spawn(
    "bun",
    [
      CLI_ENTRY,
      "mcp-proxy",
      "--name",
      opts.serverName,
      "--",
      "bun",
      "-e",
      FAKE_CHILD,
    ],
    { stdio: ["pipe", "pipe", "pipe"], env },
  );

  const stdoutLines: string[] = [];
  let stdoutBuf = "";
  child.stdout!.on("data", (c: Buffer) => {
    stdoutBuf += c.toString("utf8");
    let nl: number;
    while ((nl = stdoutBuf.indexOf("\n")) >= 0) {
      const line = stdoutBuf.slice(0, nl);
      stdoutBuf = stdoutBuf.slice(nl + 1);
      if (line.length > 0) stdoutLines.push(line);
    }
  });
  child.stderr!.on("data", () => {
    // Suppress; the child or proxy may log.
  });

  return { child, stdoutLines, daemonHits, daemonStop: stop };
}

async function send(child: ChildProcess, msg: object): Promise<void> {
  child.stdin!.write(JSON.stringify(msg) + "\n");
}

async function waitForLines(handle: ProxyHandle, count: number, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (handle.stdoutLines.length < count && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 20));
  }
}

let active: ProxyHandle | undefined;
afterEach(() => {
  if (active) {
    active.child.stdin!.end();
    active.child.kill();
    active.daemonStop();
    active = undefined;
  }
});

describe("mcp-proxy argument parsing", () => {
  test("requires --name and -- separator", () => {
    expect(() => parseProxyArgs([])).toThrow();
    expect(() => parseProxyArgs(["--name", "foo"])).toThrow(); // no `--`
    expect(() => parseProxyArgs(["--name", "foo", "--"])).toThrow(); // empty child
  });

  test("captures everything after -- as the child command", () => {
    const got = parseProxyArgs([
      "--name",
      "filesystem",
      "--",
      "npx",
      "-y",
      "@mcp/server",
      "/tmp",
    ]);
    expect(got.serverName).toBe("filesystem");
    expect(got.childCmd).toBe("npx");
    expect(got.childArgs).toEqual(["-y", "@mcp/server", "/tmp"]);
  });

  test("--name=foo equivalent form", () => {
    const got = parseProxyArgs(["--name=fs", "--", "echo", "hi"]);
    expect(got.serverName).toBe("fs");
    expect(got.childCmd).toBe("echo");
  });
});

describe("mcp-proxy passthrough", () => {
  test("initialize and tools/list pass through verbatim from child", async () => {
    active = startProxy({ serverName: "fs", daemonBehavior: "allow" });
    await send(active.child, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    await send(active.child, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    await waitForLines(active, 2);
    const init = JSON.parse(active.stdoutLines[0]!);
    const list = JSON.parse(active.stdoutLines[1]!);
    expect(init.result.serverInfo.name).toBe("fake");
    expect(list.result.tools[0].name).toBe("echo");
    // Daemon must not be hit for non-tools/call methods.
    expect(active.daemonHits.find((h) => h.path.includes("pre-tool-use"))).toBeUndefined();
  });
});

describe("mcp-proxy interception", () => {
  test("tools/call: daemon allow → child runs, response forwarded", async () => {
    active = startProxy({ serverName: "fs", daemonBehavior: "allow" });
    await send(active.child, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "echo", arguments: { msg: "hi" } },
    });
    await waitForLines(active, 1);
    const reply = JSON.parse(active.stdoutLines[0]!);
    expect(reply.id).toBe(5);
    // The fake child stamps its result with CHILD_RAN: — proves we
    // really forwarded to the child rather than synthesizing a response.
    expect(reply.result.content[0].text).toContain("CHILD_RAN:");

    const preHit = active.daemonHits.find((h) => h.path.includes("pre-tool-use"));
    expect(preHit).toBeDefined();
    expect(preHit!.body.tool_name).toBe("mcp__fs__echo");
  });

  test("tools/call: daemon deny → synthesized error, child never runs", async () => {
    active = startProxy({
      serverName: "fs",
      daemonBehavior: "deny",
      denyReason: "policy: read of /etc forbidden",
    });
    await send(active.child, {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "/etc/passwd" } },
    });
    await waitForLines(active, 1);
    const reply = JSON.parse(active.stdoutLines[0]!);
    expect(reply.id).toBe(7);
    expect(reply.result.isError).toBe(true);
    expect(reply.result.content[0].text).toContain("blocked by OpenAgentLock");
    expect(reply.result.content[0].text).toContain("read of /etc forbidden");
    // The fake child's CHILD_RAN: marker must NOT appear — proving the
    // child was bypassed entirely on deny.
    expect(reply.result.content[0].text).not.toContain("CHILD_RAN:");
  });

  test("tools/call: daemon down → fail-open, child runs", async () => {
    active = startProxy({ serverName: "fs", daemonBehavior: "down" });
    await send(active.child, {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: "echo", arguments: {} },
    });
    await waitForLines(active, 1);
    const reply = JSON.parse(active.stdoutLines[0]!);
    expect(reply.id).toBe(9);
    // Fail-open: child ran, response forwarded.
    expect(reply.result.content[0].text).toContain("CHILD_RAN:");
  });
});
