// `agentlock hook claude-code <event>` — Claude Code's command-hook shim.
// Mirrors the codex/cursor pattern: stdin JSON in, daemon round-trip,
// exit code + (on deny) reason on stderr.
//
// Why a shim instead of Claude's native HTTP hooks: when Claude was wired
// as `type: "http"` directly at the daemon, every hook fire became a
// browser-style fetch from inside Claude. A daemon outage rendered as a
// red "PreToolUse:Bash hook error / ECONNREFUSED" banner on every tool
// call. Routing through this shim lets us fail-open on transport errors
// (exit 0) and emit a one-time friendly nudge instead — matching the UX
// codex and cursor already get.
//
// Wire shape (Claude Code → daemon → Claude Code):
//   stdin:  Claude's native event JSON (session_id, hook_event_name,
//           tool_name, tool_input, tool_use_id, cwd)
//   POST:   /v1/hooks/claude-code/<event>  (raw payload forwarded verbatim)
//   reply:  daemon emits claudeHookOutput (continue/stopReason/
//           hookSpecificOutput) — the same shape Claude consumed when the
//           hook was HTTP-typed
//   stdout: on deny, the JSON envelope (Claude Code accepts either an
//           exit code OR JSON, we emit both for safety)
//   exit:   0 on allow / observability, 2 on deny

import { clearDaemonDownMarker, warnDaemonDownOnce } from "../util/daemon-warn.ts";

const ALLOWED_EVENTS = new Set([
  "session-start",
  "pre-tool-use",
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

export async function runHookClaudeCode(argv: string[]): Promise<void> {
  const event = argv[0];
  if (!event || !ALLOWED_EVENTS.has(event)) {
    process.stderr.write(
      `usage: agentlock hook claude-code <session-start|pre-tool-use|post-tool-use|stop>\n`,
    );
    process.exit(2);
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    // No payload — nothing to forward. Fail-open: let Claude continue.
    process.exit(0);
  }

  // Validate JSON locally so a malformed body doesn't waste a daemon
  // round trip. Pass through verbatim if it parses.
  try {
    JSON.parse(raw);
  } catch (e) {
    process.stderr.write(
      `agentlock hook claude-code ${event}: invalid JSON on stdin: ${(e as Error).message}\n`,
    );
    // Fail-open: invalid payload is the harness's bug, not policy.
    process.exit(0);
  }

  const url =
    defaultDaemonUrl().replace(/\/+$/, "") + `/v1/hooks/claude-code/${event}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: raw,
    });
  } catch (e) {
    warnDaemonDownOnce("claude-code", url, e as Error);
    process.exit(0); // fail-open
  }

  // Successful round-trip — re-arm the nudge for the next outage.
  clearDaemonDownMarker();

  if (!res.ok) {
    process.stderr.write(
      `agentlock hook claude-code ${event}: daemon returned ${res.status}\n`,
    );
    process.exit(0); // fail-open
  }

  let parsed: DaemonResponse;
  try {
    parsed = (await res.json()) as DaemonResponse;
  } catch (e) {
    process.stderr.write(
      `agentlock hook claude-code ${event}: malformed daemon response: ${(e as Error).message}\n`,
    );
    process.exit(0);
  }

  // SessionStart / PostToolUse / Stop are observability — the daemon
  // returns {continue: true} unconditionally. Only PreToolUse can deny.
  const decision = parsed.hookSpecificOutput?.permissionDecision;
  if (decision === "deny") {
    const reason =
      parsed.hookSpecificOutput?.permissionDecisionReason ??
      parsed.stopReason ??
      "blocked by OpenAgentLock policy";
    process.stderr.write(`${reason}\n`);
    // Claude Code reads either the JSON body OR the exit code. Emit both
    // so future Claude versions that prefer one over the other still see
    // a deny.
    process.stdout.write(JSON.stringify(parsed) + "\n");
    process.exit(2);
  }

  // Allow path. Some Claude events don't carry hookSpecificOutput; just
  // exit 0 silently. Stdout stays empty so we don't perturb Claude's
  // own logging.
  process.exit(0);
}
