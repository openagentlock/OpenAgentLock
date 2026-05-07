// `agentlock mcp-server` — minimal MCP stdio server for Claude Desktop.
//
// Claude Desktop has no PreToolUse / PostToolUse hook surface upstream
// (anthropics/claude-code#45514, closed without ship). The only way to
// register agentlock is as an MCP server entry in
// claude_desktop_config.json. That gives us no enforcement — Claude
// will not ask us before running its own tools — but it gives an
// observability surface: when Claude is steered into invoking one of
// our tools, we see it and can forward to the daemon.
//
// Scope is intentionally narrow. We expose two read-only tools backed
// by the daemon's existing /v1/health and /v1/ledger/tail endpoints. We
// do NOT expose anything that mutates state or claims to gate other
// tools — that would mislead users about what this surface can do.
//
// MCP transport: JSON-RPC 2.0 over stdin/stdout, newline-delimited.
// We implement only the methods Claude Desktop sends in practice:
// initialize, notifications/initialized, tools/list, tools/call,
// shutdown. Anything else returns -32601 Method not found.

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "agentlock", version: "0.1.0" };

function defaultDaemonUrl(): string {
  return (
    process.env.AGENTLOCK_DAEMON_URL ??
    process.env.AGENTLOCK_CONTROL_PLANE_URL ??
    "http://127.0.0.1:7878"
  );
}

const TOOLS = [
  {
    name: "agentlock_status",
    description:
      "Probe the OpenAgentLock daemon. Returns reachable=true/false plus the daemon's reported status. Read-only.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "agentlock_recent_decisions",
    description:
      "Return the last N entries from the OpenAgentLock ledger (verdicts, signers, tool names). Read-only. Defaults to 20, max 100.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 100, default: 20 },
      },
      required: [],
    },
  },
] as const;

async function callStatus(): Promise<{
  content: Array<{ type: "text"; text: string }>;
}> {
  const url = defaultDaemonUrl().replace(/\/+$/, "") + "/v1/health";
  try {
    const res = await fetch(url, { method: "GET" });
    if (!res.ok) {
      return mcpText(`daemon ${url} returned ${res.status}`);
    }
    const body = (await res.json()) as { status?: string };
    return mcpText(
      `daemon reachable at ${defaultDaemonUrl()} (status=${body.status ?? "unknown"})`,
    );
  } catch (e) {
    return mcpText(`daemon unreachable at ${defaultDaemonUrl()}: ${(e as Error).message}`);
  }
}

async function callRecentDecisions(
  args: Record<string, unknown> | undefined,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
  const rawLimit = args?.limit;
  let limit = 20;
  if (typeof rawLimit === "number" && Number.isFinite(rawLimit)) {
    limit = Math.max(1, Math.min(100, Math.floor(rawLimit)));
  }
  const url =
    defaultDaemonUrl().replace(/\/+$/, "") + `/v1/ledger/tail?limit=${limit}`;
  try {
    const res = await fetch(url, { method: "GET" });
    if (!res.ok) {
      return mcpText(`daemon ${url} returned ${res.status}`);
    }
    const body = await res.text();
    return mcpText(body);
  } catch (e) {
    return mcpText(`daemon unreachable: ${(e as Error).message}`);
  }
}

function mcpText(text: string): { content: Array<{ type: "text"; text: string }> } {
  return { content: [{ type: "text", text }] };
}

function send(res: JsonRpcResponse): void {
  process.stdout.write(JSON.stringify(res) + "\n");
}

function reply(id: JsonRpcResponse["id"], result: unknown): void {
  send({ jsonrpc: "2.0", id, result });
}

function fail(id: JsonRpcResponse["id"], code: number, message: string): void {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

async function dispatch(req: JsonRpcRequest): Promise<void> {
  const id = req.id ?? null;
  switch (req.method) {
    case "initialize":
      reply(id, {
        protocolVersion: PROTOCOL_VERSION,
        // Tools only — we don't expose resources or prompts. Declaring
        // the empty objects would advertise capabilities we don't serve.
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
      return;
    case "notifications/initialized":
    case "initialized":
      // Notifications carry no id and expect no reply.
      return;
    case "tools/list":
      reply(id, { tools: TOOLS });
      return;
    case "tools/call": {
      const params = (req.params ?? {}) as {
        name?: string;
        arguments?: Record<string, unknown>;
      };
      if (params.name === "agentlock_status") {
        reply(id, await callStatus());
        return;
      }
      if (params.name === "agentlock_recent_decisions") {
        reply(id, await callRecentDecisions(params.arguments));
        return;
      }
      fail(id, -32602, `unknown tool: ${params.name ?? "<missing>"}`);
      return;
    }
    case "shutdown":
      reply(id, null);
      return;
    case "exit":
      process.exit(0);
    default:
      // Notifications (no id) silently drop; requests get -32601.
      if (req.id !== undefined && req.id !== null) {
        fail(id, -32601, `method not found: ${req.method}`);
      }
  }
}

export async function runMcpServer(): Promise<void> {
  // MCP stdio transport is newline-delimited JSON-RPC. Buffer until we
  // see a newline so payloads spanning multiple chunks parse cleanly.
  let buf = "";
  for await (const chunk of process.stdin) {
    buf += (chunk as Buffer).toString("utf8");
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let req: JsonRpcRequest;
      try {
        req = JSON.parse(line) as JsonRpcRequest;
      } catch {
        // Parse errors with no id can't be replied to. Drop and continue.
        continue;
      }
      try {
        await dispatch(req);
      } catch (e) {
        if (req.id !== undefined && req.id !== null) {
          fail(req.id, -32603, (e as Error).message);
        }
      }
    }
  }
}
