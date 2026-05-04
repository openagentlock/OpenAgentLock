// `agentlock hook gemini <event>` — bridge between Gemini CLI's command-
// hook contract (stdin JSON + exit codes) and the daemon's HTTP hook
// endpoints. Gemini spawns this binary, writes the hook payload to
// stdin, and reads exit code + stdout JSON.
//
// Mapping:
//   allow → exit 0, EMPTY stdout. Critical: Gemini parses stdout as a
//           JSON envelope ({"decision":..., "reason":...}); writing
//           anything non-JSON would error the harness, and writing an
//           allow envelope is at best redundant noise. Stay silent.
//   deny  → exit 2 with `reason` on stderr (Gemini surfaces stderr as
//           the system block reason on exit 2) AND the full daemon
//           response JSON on stdout (so future Gemini versions that
//           prefer the JSON path over the exit-code path still see it).
//
// Daemon URL comes from $AGENTLOCK_DAEMON_URL (set in the env stanza
// the installer writes into ~/.gemini/settings.json) with a loopback
// default. Any transport / parse failure exits 0 — fail-open at the
// shim layer keeps a daemon outage from soft-bricking the user's coding
// session. The daemon-side ledger is the source of truth.
//
// Response shape differs from Claude/Codex: Gemini uses flat
// `{decision, reason}` (NOT Claude's nested `hookSpecificOutput.
// permissionDecision`). The daemon emits the Gemini shape directly.
//
// Gemini has no statusLine analog (Claude's persistent UI element under
// the chat). Even on the deny path we keep stderr to the bare reason —
// no banner, no decoration — because Gemini will render it verbatim to
// the model.

const ALLOWED_EVENTS = new Set([
  "session-start",
  "pre-tool-use",
  "post-tool-use",
  "stop",
]);

interface DaemonResponse {
  continue?: boolean;
  stopReason?: string;
  decision?: "allow" | "deny";
  reason?: string;
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

export async function runHookGemini(argv: string[]): Promise<void> {
  const event = argv[0];
  if (!event || !ALLOWED_EVENTS.has(event)) {
    process.stderr.write(
      `usage: agentlock hook gemini <session-start|pre-tool-use|post-tool-use|stop>\n`,
    );
    process.exit(2);
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    // No payload — nothing to forward. Fail-open: let Gemini continue.
    process.exit(0);
  }

  try {
    JSON.parse(raw);
  } catch (e) {
    process.stderr.write(
      `agentlock hook gemini ${event}: invalid JSON on stdin: ${(e as Error).message}\n`,
    );
    // Fail-open: invalid payload is the harness's bug, not policy.
    process.exit(0);
  }

  const url = defaultDaemonUrl().replace(/\/+$/, "") + `/v1/hooks/gemini/${event}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: raw,
    });
  } catch {
    // Daemon unreachable — silent fail-open. No stdout (Gemini parses
    // stdout as JSON; any garbage would error the harness). No stderr
    // either: on exit 0 Gemini may still surface stderr text in some
    // builds, and an "offline" line would alarm without being
    // actionable from inside the model loop.
    process.exit(0);
  }

  if (!res.ok) {
    process.stderr.write(
      `agentlock hook gemini ${event}: daemon returned ${res.status}\n`,
    );
    process.exit(0); // fail-open
  }

  let parsed: DaemonResponse;
  try {
    parsed = (await res.json()) as DaemonResponse;
  } catch (e) {
    process.stderr.write(
      `agentlock hook gemini ${event}: malformed daemon response: ${(e as Error).message}\n`,
    );
    process.exit(0);
  }

  // PostToolUse / SessionStart / Stop are observability — the daemon
  // returns {continue: true} (and may include decision: "allow")
  // unconditionally. Only PreToolUse can deny. Treat any non-`deny`
  // value (including missing) as allow.
  if (parsed.decision === "deny") {
    const reason =
      parsed.reason ??
      parsed.stopReason ??
      "blocked by OpenAgentLock policy";
    process.stderr.write(`${reason}\n`);
    // Emit the JSON body too so future Gemini versions that prefer
    // stdout-JSON over exit-code see a consistent deny envelope.
    process.stdout.write(JSON.stringify(parsed) + "\n");
    process.exit(2);
  }

  // Allow path. Stay silent on stdout — Gemini parses stdout as JSON,
  // and a bare "allow" envelope is at best redundant noise.
  process.exit(0);
}
