// `agentlock hook codex <event>` — the bridge between Codex CLI's
// command-hook contract (stdin JSON + exit codes) and the daemon's HTTP
// hook endpoints. Codex spawns this binary, writes the hook payload to
// stdin, and reads exit code + stderr.
//
// Mapping:
//   allow → exit 0
//   deny  → exit 2 with permissionDecisionReason on stderr; the
//           hookSpecificOutput JSON is also written to stdout for
//           harnesses that read it (per docs/reference/hook-daemon-path.md).
//
// Daemon URL comes from $AGENTLOCK_DAEMON_URL (set in the env stanza
// the installer writes into hooks.json) with a loopback default. Any
// transport failure exits 0 — fail-open at the shim layer keeps a
// daemon outage from soft-bricking the user's coding session. The
// daemon-side ledger is the source of truth; if it can't be reached,
// monitor mode is the safer default than blocking everything.

import { clearDaemonDownMarker, warnDaemonDownOnce } from "../util/daemon-warn.ts";

const ALLOWED_EVENTS = new Set([
  "session-start",
  "pre-tool-use",
  "post-tool-use",
  "stop",
]);

interface CodexHookSpecifics {
  hookEventName?: string;
  permissionDecision?: "allow" | "deny";
  permissionDecisionReason?: string;
}

interface DaemonResponse {
  continue?: boolean;
  stopReason?: string;
  hookSpecificOutput?: CodexHookSpecifics;
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

export async function runHookCodex(argv: string[]): Promise<void> {
  const event = argv[0];
  if (!event || !ALLOWED_EVENTS.has(event)) {
    process.stderr.write(
      `usage: agentlock hook codex <session-start|pre-tool-use|post-tool-use|stop>\n`,
    );
    process.exit(2);
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    // No payload — nothing to forward. Fail-open: let Codex continue.
    process.exit(0);
  }

  // Validate JSON locally so a malformed body doesn't waste a daemon
  // round trip. Pass through verbatim if it parses.
  try {
    JSON.parse(raw);
  } catch (e) {
    process.stderr.write(
      `agentlock hook codex ${event}: invalid JSON on stdin: ${(e as Error).message}\n`,
    );
    // Fail-open: invalid payload is the harness's bug, not policy.
    process.exit(0);
  }

  const url = defaultDaemonUrl().replace(/\/+$/, "") + `/v1/hooks/codex/${event}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: raw,
    });
  } catch (e) {
    warnDaemonDownOnce("codex", url, e as Error);
    process.exit(0); // fail-open
  }

  // Successful round-trip — re-arm the nudge for the next outage.
  clearDaemonDownMarker();

  if (!res.ok) {
    process.stderr.write(
      `agentlock hook codex ${event}: daemon returned ${res.status}\n`,
    );
    process.exit(0); // fail-open
  }

  let parsed: DaemonResponse;
  try {
    parsed = (await res.json()) as DaemonResponse;
  } catch (e) {
    process.stderr.write(
      `agentlock hook codex ${event}: malformed daemon response: ${(e as Error).message}\n`,
    );
    process.exit(0);
  }

  // PostToolUse / SessionStart / Stop are observability — the daemon
  // returns {continue: true} unconditionally. Only PreToolUse can deny.
  const decision = parsed.hookSpecificOutput?.permissionDecision;
  if (decision === "deny") {
    const reason =
      parsed.hookSpecificOutput?.permissionDecisionReason ??
      parsed.stopReason ??
      "blocked by OpenAgentLock policy";
    process.stderr.write(`${reason}\n`);
    // Codex reads either the JSON body OR the exit code. Emit both so
    // future Codex versions that prefer one over the other still see a
    // deny.
    process.stdout.write(JSON.stringify(parsed) + "\n");
    process.exit(2);
  }

  // Allow path. Some Codex events don't carry hookSpecificOutput; just
  // exit 0 silently. Stdout stays empty so we don't perturb Codex's
  // own logging.
  process.exit(0);
}
