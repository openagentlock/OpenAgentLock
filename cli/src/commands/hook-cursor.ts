// `agentlock hook cursor <event>` — Cursor IDE's command-hook bridge to
// the daemon. Cursor (≥1.7) spawns this binary, writes the hook payload
// to stdin, and reads exit code + stdout JSON to decide whether the tool
// call (or shell exec, or MCP call) proceeds.
//
// Wire shape (Cursor → daemon → Cursor):
//   stdin:  Cursor's native event JSON (e.g. preToolUse with
//           conversation_id / generation_id / tool_use_id)
//   POST:   /v1/hooks/cursor/<event>  (raw payload forwarded verbatim)
//   reply:  daemon emits the shared claudeHookOutput envelope
//   stdout: Cursor's expected {permission, agent_message?} shape
//   exit:   0 on allow, 2 on deny — Cursor reads either, both for safety
//
// Cursor exposes a dedicated `ask` permission, but ADR 0018 forbids
// in-harness approval prompts. We map daemon `ask` → Cursor `deny` with
// a fixed reason pointing at the dashboard.
//
// Failure modes are fail-open (exit 0). The daemon's ledger is the source
// of truth; a missing daemon should not soft-brick the user's IDE.
// Operators who want fail-closed semantics can install with
// `failClosed: true` in the wired hook entries — Cursor will then treat
// any exit-code error as a deny regardless of what we write to stdout.

const ALLOWED_EVENTS = new Set([
  "session-start",
  "pre-tool-use",
  "before-shell-execution",
  "before-mcp-execution",
  "after-mcp-execution",
  "post-tool-use",
  "stop",
]);

interface ClaudeHookSpecifics {
  hookEventName?: string;
  permissionDecision?: "allow" | "deny" | "ask";
  permissionDecisionReason?: string;
}

interface DaemonResponse {
  continue?: boolean;
  stopReason?: string;
  hookSpecificOutput?: ClaudeHookSpecifics;
}

function defaultDaemonUrl(): string {
  return (
    process.env.AGENTLOCK_DAEMON_URL ??
    process.env.AGENTLOCK_CONTROL_PLANE_URL ??
    "http://127.0.0.1:7878"
  );
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function emitAllow(): never {
  process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n");
  process.exit(0);
}

function emitDeny(reason: string): never {
  process.stderr.write(`${reason}\n`);
  process.stdout.write(
    JSON.stringify({ permission: "deny", agent_message: reason }) + "\n",
  );
  process.exit(2);
}

export async function runHookCursor(argv: string[]): Promise<void> {
  const event = argv[0];
  if (!event || !ALLOWED_EVENTS.has(event)) {
    process.stderr.write(
      `usage: agentlock hook cursor <session-start|pre-tool-use|before-shell-execution|before-mcp-execution|after-mcp-execution|post-tool-use|stop>\n`,
    );
    process.exit(2);
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    // No payload — nothing to forward. Fail-open: let Cursor continue.
    process.exit(0);
  }

  // Validate JSON locally so a malformed body doesn't waste a daemon
  // round trip. Pass through verbatim if it parses.
  try {
    JSON.parse(raw);
  } catch (e) {
    process.stderr.write(
      `agentlock hook cursor ${event}: invalid JSON on stdin: ${(e as Error).message}\n`,
    );
    // Fail-open: invalid payload is the harness's bug, not policy.
    process.exit(0);
  }

  const url =
    defaultDaemonUrl().replace(/\/+$/, "") + `/v1/hooks/cursor/${event}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: raw,
    });
  } catch (e) {
    process.stderr.write(
      `agentlock hook cursor ${event}: daemon unreachable at ${url}: ${(e as Error).message}\n`,
    );
    process.exit(0); // fail-open
  }

  if (!res.ok) {
    process.stderr.write(
      `agentlock hook cursor ${event}: daemon returned ${res.status}\n`,
    );
    process.exit(0); // fail-open
  }

  let parsed: DaemonResponse;
  try {
    parsed = (await res.json()) as DaemonResponse;
  } catch (e) {
    process.stderr.write(
      `agentlock hook cursor ${event}: malformed daemon response: ${(e as Error).message}\n`,
    );
    process.exit(0);
  }

  // Only PreToolUse / shell / MCP gates can deny. Observability events
  // (session-start, post-tool-use, after-mcp-execution, stop) come back
  // with {continue: true} and no permissionDecision — exit 0 silently.
  const decision = parsed.hookSpecificOutput?.permissionDecision;
  if (decision === "deny") {
    const reason =
      parsed.hookSpecificOutput?.permissionDecisionReason ??
      parsed.stopReason ??
      "blocked by OpenAgentLock policy";
    emitDeny(reason);
  }
  if (decision === "ask") {
    // ADR 0018: no in-harness approval prompts. Map to deny with a
    // fixed reason directing the user to the dashboard.
    emitDeny("approval pending — use dashboard");
  }

  // Allow path. Some Cursor events don't carry hookSpecificOutput at
  // all (the daemon returns plain {continue: true}); treat that the
  // same as an explicit allow.
  if (decision === "allow") {
    emitAllow();
  }
  process.exit(0);
}
