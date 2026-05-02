// One-time "daemon is down" nudge for hook shims (codex / cursor / claude-code).
//
// The shims fail-open on ECONNREFUSED so the user's session keeps working,
// but silent fail-open means a user with the daemon stopped has no idea
// they're running unprotected. This helper writes one friendly stderr line
// the first time a session can't reach the daemon, then stays silent —
// gated by a marker file under agentlockHome(). The marker is cleared the
// next time any shim talks to the daemon successfully, so the nudge fires
// again on the next outage.
//
// stderr is the right surface here: every harness we wire (Codex, Cursor,
// Claude Code) renders shim stderr in its own log/UI. The shims keep
// process.exit(0) regardless — this helper is for the message only.
//
// We intentionally don't try to be clever about *which* harness suppresses
// the marker. One marker, one message per outage, across all harnesses.
// If a user runs codex and cursor concurrently, they get the nudge once.
// That matches user mental model: "OAL is down" is global, not per-tool.
//
// Failures inside the helper itself (e.g. mkdir -p denied) are swallowed.
// We never want the nudge path to add a new failure mode on top of the
// daemon outage we're already trying to soften.

import { existsSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { agentlockHome } from "./paths.ts";

function markerPath(): string {
  return join(agentlockHome(), "daemon-down-warned");
}

export function warnDaemonDownOnce(harness: string, url: string, err: Error): void {
  const path = markerPath();
  if (existsSync(path)) return;
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, new Date().toISOString() + "\n", { flag: "w" });
  } catch {
    // Best-effort: if we can't write the marker, we'd nudge every
    // invocation. Better than crashing the shim path.
  }
  process.stderr.write(
    `OpenAgentLock daemon isn't running — ${harness} is running unprotected.\n` +
      `  Tried: ${url}  (${err.message})\n` +
      `  Start it with \`docker compose up -d\` or see https://openagentlock.github.io/OpenAgentLock/guide/installation/.\n` +
      `  (This message shows once per outage.)\n`,
  );
}

// Called from the shim when a daemon round-trip succeeds. Cheap no-op when
// the marker isn't there. Re-arms the nudge for the next outage.
export function clearDaemonDownMarker(): void {
  const path = markerPath();
  if (!existsSync(path)) return;
  try {
    unlinkSync(path);
  } catch {
    // Same posture as warn: best-effort.
  }
}
