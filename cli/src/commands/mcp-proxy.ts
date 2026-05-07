// `agentlock mcp-proxy --name <id> -- <child-cmd> <child-args...>`
//
// Stdio proxy that sits between Claude Desktop and a real MCP server.
// Spawned by Claude Desktop after `agentlock install` rewrites the
// user's claude_desktop_config.json so every entry points at this proxy
// instead of at the original command. Original command + args + env are
// preserved in the same config under `_agentlock_original` so uninstall
// can restore them.
//
// Wire shape:
//   * stdin  ← Claude Desktop's JSON-RPC frames (newline-delimited)
//   * stdout → frames going back to Claude Desktop
//   * child stdin/stdout ↔ the real MCP server we spawned
//
// We pass everything through verbatim EXCEPT JSON-RPC requests with
// method "tools/call" — those we pause, POST to the daemon's
// /v1/hooks/claude-desktop/pre-tool-use, and either:
//   * allow → forward to child; on the child's response, fire-and-
//     forget POST /post-tool-use for ledger completeness
//   * deny  → synthesize an MCP tool error reply ({isError:true, ...})
//     using the same JSON-RPC id, send it directly back to Claude, and
//     never wake the child
//
// Daemon-down posture: fail-open (matches the Claude Code shim). A
// daemon outage MUST NOT brick a user's Desktop app — the dashboard's
// "daemon offline" banner is the user-visible signal, not a flood of
// blocked tool calls. Per-server fail-closed is a future feature.

import { spawn } from "node:child_process";

interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface DaemonHookResponse {
  continue?: boolean;
  stopReason?: string;
  hookSpecificOutput?: {
    permissionDecision?: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
  };
}

interface ProxyArgs {
  serverName: string;
  childCmd: string;
  childArgs: string[];
}

function defaultDaemonUrl(): string {
  return (
    process.env.AGENTLOCK_DAEMON_URL ??
    process.env.AGENTLOCK_CONTROL_PLANE_URL ??
    "http://127.0.0.1:7878"
  );
}

// sessionId is stable per-server-name so Claude Desktop's auto-launched
// proxies attach to a deterministic daemon-side session rather than
// minting a new one on every start. The daemon's auto-create path tags
// these signer="none" — they show up on the dashboard with the same
// red unattested banner Claude Code's auto-sessions get.
function sessionIdFor(serverName: string): string {
  return `claude-desktop-${serverName}`.slice(0, 128);
}

// parseProxyArgs accepts either:
//   --name <id> -- <cmd> <args...>
//   --name=<id> -- <cmd> <args...>
// Anything after the first standalone "--" is the child command.
export function parseProxyArgs(argv: string[]): ProxyArgs {
  let serverName = "";
  let i = 0;
  while (i < argv.length) {
    const a = argv[i]!;
    if (a === "--") {
      i++;
      break;
    }
    if (a === "--name") {
      serverName = argv[i + 1] ?? "";
      i += 2;
      continue;
    }
    if (a.startsWith("--name=")) {
      serverName = a.slice("--name=".length);
      i++;
      continue;
    }
    throw new Error(`unrecognized arg: ${a}`);
  }
  const rest = argv.slice(i);
  if (!serverName) throw new Error("missing --name <id>");
  if (rest.length === 0) throw new Error("missing -- <child-cmd> ...");
  return { serverName, childCmd: rest[0]!, childArgs: rest.slice(1) };
}

// mcpToolName converts an MCP tools/call into the Claude Code-style
// `mcp__<server>__<tool>` namespacing so policy rules written for one
// surface match the other.
function mcpToolName(serverName: string, toolName: string): string {
  return `mcp__${serverName}__${toolName}`;
}

// callPreToolUse asks the daemon whether a tools/call should run.
// Returns the decision; a transport / 5xx / parse error returns "allow"
// so a daemon outage fails-open (see file header).
async function callPreToolUse(
  daemonUrl: string,
  serverName: string,
  sessionId: string,
  msg: JsonRpcMessage,
): Promise<{ decision: "allow" | "deny" | "ask"; reason: string }> {
  const params = (msg.params ?? {}) as { name?: string; arguments?: unknown };
  const toolName = mcpToolName(serverName, params.name ?? "<unknown>");
  const body = {
    session_id: sessionId,
    hook_event_name: "PreToolUse",
    tool_name: toolName,
    tool_input: (params.arguments ?? {}) as Record<string, unknown>,
    tool_use_id: String(msg.id ?? "0"),
    cwd: process.cwd(),
  };
  try {
    const res = await fetch(
      daemonUrl.replace(/\/+$/, "") + "/v1/hooks/claude-desktop/pre-tool-use",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) return { decision: "allow", reason: "" };
    const parsed = (await res.json()) as DaemonHookResponse;
    const decision = parsed.hookSpecificOutput?.permissionDecision ?? "allow";
    const reason =
      parsed.hookSpecificOutput?.permissionDecisionReason ??
      parsed.stopReason ??
      "";
    return { decision, reason };
  } catch {
    // Fail-open: a daemon outage must not brick the Desktop app.
    return { decision: "allow", reason: "" };
  }
}

// recordPostToolUse fires off completion telemetry. Best-effort: we
// don't await this on the hot path, and we never propagate errors back
// to the child or the host — the tool call already ran.
function recordPostToolUse(
  daemonUrl: string,
  serverName: string,
  sessionId: string,
  toolName: string,
  toolUseId: string,
  toolResponse: unknown,
): void {
  const body = {
    session_id: sessionId,
    hook_event_name: "PostToolUse",
    tool_name: mcpToolName(serverName, toolName),
    tool_input: {},
    tool_use_id: toolUseId,
    tool_response: toolResponse,
  };
  fetch(
    daemonUrl.replace(/\/+$/, "") + "/v1/hooks/claude-desktop/post-tool-use",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  ).catch(() => {
    // Silent: ledger gap is acceptable, blocking a tool response on it
    // would defeat the fail-open posture above.
  });
}

// denyResponseFor synthesizes an MCP tool-error reply matching the
// caller's id. Claude Desktop renders this as a tool failure with the
// supplied text — the model sees it as a normal "tool returned an
// error" outcome and can react in conversation.
function denyResponseFor(id: number | string | null, reason: string): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      isError: true,
      content: [
        {
          type: "text",
          text: `blocked by OpenAgentLock policy: ${reason || "denied"}`,
        },
      ],
    },
  };
}

// LineBuffer accumulates byte chunks and emits complete newline-
// delimited lines. MCP stdio frames are guaranteed not to contain
// embedded newlines (per spec) so a simple split is safe.
class LineBuffer {
  private buf = "";
  push(chunk: Buffer | string): string[] {
    this.buf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    const out: string[] = [];
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + 1);
      if (line.length > 0) out.push(line);
    }
    return out;
  }
}

export async function runMcpProxy(argv: string[]): Promise<void> {
  let parsed: ProxyArgs;
  try {
    parsed = parseProxyArgs(argv);
  } catch (e) {
    process.stderr.write(
      `agentlock mcp-proxy: ${(e as Error).message}\n` +
        `usage: agentlock mcp-proxy --name <id> -- <child-cmd> [args...]\n`,
    );
    process.exit(2);
  }

  const daemonUrl = defaultDaemonUrl();
  const sessionId = sessionIdFor(parsed.serverName);

  const child = spawn(parsed.childCmd, parsed.childArgs, {
    stdio: ["pipe", "pipe", "inherit"],
  });

  child.on("error", (err) => {
    // The configured child command can't even be spawned (ENOENT, permission
    // denied, etc.). Surface to stderr and exit so Claude Desktop logs the
    // reason rather than seeing silent stdout closure.
    process.stderr.write(
      `agentlock mcp-proxy: failed to spawn ${parsed.childCmd}: ${err.message}\n`,
    );
    process.exit(2);
  });

  child.on("exit", (code, signal) => {
    // Mirror the child's termination to our parent so Claude Desktop's
    // server-died detection works the same as it would without the proxy.
    if (signal) process.kill(process.pid, signal);
    else process.exit(code ?? 0);
  });

  // Track the in-flight tool/call ids so we can fire post-tool-use when
  // the matching response comes back from the child. Map keyed by
  // JSON-RPC id (stringified to handle mixed numeric/string ids).
  const pendingToolCalls = new Map<string, { name: string; toolUseId: string }>();

  // Claude Desktop → us → child
  const stdinBuf = new LineBuffer();
  process.stdin.on("data", async (chunk: Buffer) => {
    for (const line of stdinBuf.push(chunk)) {
      let msg: JsonRpcMessage;
      try {
        msg = JSON.parse(line) as JsonRpcMessage;
      } catch {
        // Pass malformed lines through — the child will reject them and
        // we don't want to silently drop messages we don't understand.
        child.stdin.write(line + "\n");
        continue;
      }
      if (msg.method === "tools/call" && msg.id !== undefined && msg.id !== null) {
        const params = (msg.params ?? {}) as {
          name?: string;
          arguments?: unknown;
        };
        const { decision, reason } = await callPreToolUse(
          daemonUrl,
          parsed.serverName,
          sessionId,
          msg,
        );
        if (decision === "deny") {
          // Short-circuit: respond directly to Claude, don't wake child.
          process.stdout.write(JSON.stringify(denyResponseFor(msg.id, reason)) + "\n");
          continue;
        }
        // Allow / ask → forward and remember the id so the response
        // path can fire post-tool-use.
        pendingToolCalls.set(String(msg.id), {
          name: params.name ?? "<unknown>",
          toolUseId: String(msg.id),
        });
        child.stdin.write(line + "\n");
        continue;
      }
      child.stdin.write(line + "\n");
    }
  });
  process.stdin.on("end", () => {
    child.stdin.end();
  });

  // Child → us → Claude Desktop
  const childStdoutBuf = new LineBuffer();
  child.stdout.on("data", (chunk: Buffer) => {
    for (const line of childStdoutBuf.push(chunk)) {
      // Forward verbatim before doing any post-processing — Claude
      // Desktop's UX is sensitive to latency and we don't want a
      // ledger-write to add noticeable lag.
      process.stdout.write(line + "\n");

      let msg: JsonRpcMessage;
      try {
        msg = JSON.parse(line) as JsonRpcMessage;
      } catch {
        continue;
      }
      if (msg.id === undefined || msg.id === null) continue;
      const pending = pendingToolCalls.get(String(msg.id));
      if (!pending) continue;
      pendingToolCalls.delete(String(msg.id));
      // Fire-and-forget post-tool-use telemetry. result OR error is
      // fine — summarizeToolResponse on the daemon side handles both.
      recordPostToolUse(
        daemonUrl,
        parsed.serverName,
        sessionId,
        pending.name,
        pending.toolUseId,
        msg.result ?? msg.error,
      );
    }
  });
}
