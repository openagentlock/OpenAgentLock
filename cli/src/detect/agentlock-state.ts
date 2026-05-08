// Helpers for figuring out whether agentlock is already wired into a
// harness on disk, and which daemon URL it currently points at. Used by
// detectors so the install picker can pre-check rows that are already
// installed and show "wired -> http://..." next to them.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";

export interface AgentlockState {
  installed: boolean;
  daemonURL?: string;
}

const NOT_INSTALLED: AgentlockState = { installed: false };

function originOf(u: string): string {
  try {
    return new URL(u).origin;
  } catch {
    return u;
  }
}

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

export function claudeDesktopAgentlockState(configPath: string): AgentlockState {
  if (!existsSync(configPath)) return NOT_INSTALLED;
  let raw: string;
  try {
    raw = readFileSync(configPath, "utf8");
  } catch {
    return NOT_INSTALLED;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return NOT_INSTALLED;
  }
  const servers = (parsed as { mcpServers?: Record<string, unknown> }).mcpServers;
  if (!servers || typeof servers !== "object") return NOT_INSTALLED;

  for (const name of Object.keys(servers)) {
    const entry = servers[name];
    if (!entry || typeof entry !== "object") continue;
    const e = entry as Record<string, unknown>;
    if (e._agentlock !== true) continue;
    const env = (e.env as Record<string, unknown> | undefined) ?? undefined;
    const url = env && typeof env.AGENTLOCK_DAEMON_URL === "string"
      ? env.AGENTLOCK_DAEMON_URL
      : undefined;
    return { installed: true, daemonURL: url ? originOf(url) : undefined };
  }
  return NOT_INSTALLED;
}

export function codexAgentlockState(hooksPath: string): AgentlockState {
  if (!existsSync(hooksPath)) return NOT_INSTALLED;
  let raw: string;
  try {
    raw = readFileSync(hooksPath, "utf8");
  } catch {
    return NOT_INSTALLED;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return NOT_INSTALLED;
  }
  const root =
    parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  const hooks =
    root.hooks && typeof root.hooks === "object"
      ? (root.hooks as Record<string, unknown>)
      : root;
  for (const list of Object.values(hooks)) {
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      if (!entry || typeof entry !== "object") continue;
      const e = entry as Record<string, unknown>;
      if (e._agentlock !== true) continue;
      const inner = Array.isArray(e.hooks) ? (e.hooks as unknown[]) : [];
      for (const h of inner) {
        if (!h || typeof h !== "object") continue;
        const hook = h as { env?: unknown };
        const env = hook.env;
        if (env && typeof env === "object") {
          const url = (env as { AGENTLOCK_DAEMON_URL?: unknown }).AGENTLOCK_DAEMON_URL;
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
    return { installed: true };
  }
}

export function devStubStateForHarness(harnessID: string): AgentlockState {
  return devStubAgentlockState(join(home(), "." + harnessID));
}
