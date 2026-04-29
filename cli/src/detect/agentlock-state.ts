// Helpers for figuring out whether agentlock is already wired into a
// harness on disk, and which daemon URL it currently points at. Used by
// detectors so the install picker can pre-check rows that are already
// installed and show "wired → http://..." next to them.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";

export interface AgentlockState {
  installed: boolean;
  daemonURL?: string;
}

const NOT_INSTALLED: AgentlockState = { installed: false };

// originOf returns scheme://host[:port] for a parseable URL, or the
// original string if URL parsing fails. Lets us collapse a per-hook
// URL like "http://127.0.0.1:7878/v1/hooks/claude-code/pre-tool-use"
// down to "http://127.0.0.1:7878" for the picker sub-line.
function originOf(u: string): string {
  try {
    return new URL(u).origin;
  } catch {
    return u;
  }
}

// claudeAgentlockState reads a Claude Code settings.json and reports
// whether agentlock-tagged hook entries (the `_agentlock: true` marker
// applyClaudeCode writes) are present, plus the daemon URL if we can
// pull one out of any embedded HTTP hook.
export function claudeAgentlockState(settingsPath: string): AgentlockState {
  if (!existsSync(settingsPath)) return NOT_INSTALLED;
  let raw: string;
  try {
    raw = readFileSync(settingsPath, "utf8");
  } catch {
    return NOT_INSTALLED;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return NOT_INSTALLED;
  }
  const hooks = (parsed as { hooks?: Record<string, unknown> }).hooks;
  if (!hooks || typeof hooks !== "object") return NOT_INSTALLED;

  for (const event of Object.keys(hooks)) {
    const list = (hooks as Record<string, unknown>)[event];
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      if (!entry || typeof entry !== "object") continue;
      const e = entry as Record<string, unknown>;
      if (e._agentlock !== true) continue;
      // Prefer the URL from the first nested HTTP hook so the picker can
      // surface "wired → http://...:7878" without rendering all of them.
      // Strip the per-hook path (`/v1/hooks/...`) so the picker only
      // shows the daemon origin — that's the part the user is choosing.
      const inner = Array.isArray(e.hooks) ? (e.hooks as unknown[]) : [];
      for (const h of inner) {
        if (h && typeof h === "object") {
          const url = (h as { url?: unknown }).url;
          if (typeof url === "string" && url.length > 0) {
            return { installed: true, daemonURL: originOf(url) };
          }
        }
      }
      return { installed: true };
    }
  }
  return NOT_INSTALLED;
}

// devStubAgentlockState reads `.agentlock-dev.json` from a non-claude
// harness's dev sandbox dir. The daemon's apply pipeline writes that
// marker for harnesses without a real installer yet. Presence + the
// stamped daemon_url are enough for the picker.
export function devStubAgentlockState(harnessDir: string): AgentlockState {
  const marker = join(harnessDir, ".agentlock-dev.json");
  if (!existsSync(marker)) return NOT_INSTALLED;
  try {
    const parsed = JSON.parse(readFileSync(marker, "utf8")) as {
      agentlock_dev?: boolean;
      daemon_url?: unknown;
    };
    if (parsed.agentlock_dev !== true) return NOT_INSTALLED;
    const url = typeof parsed.daemon_url === "string" ? parsed.daemon_url : undefined;
    return { installed: true, daemonURL: url };
  } catch {
    // Marker exists but is unparseable — treat as installed without a
    // URL so the picker still flags it. Better than hiding partial
    // state from the user.
    return { installed: true };
  }
}

// devStubStateForHarness mirrors the daemon's devStubDir layout: every
// non-claude harness writes its marker under `<home>/.<harnessId>/`.
// Detectors call this with their HarnessId to get the same answer the
// install picker needs without hand-rolling paths.
export function devStubStateForHarness(harnessID: string): AgentlockState {
  return devStubAgentlockState(join(home(), "." + harnessID));
}
