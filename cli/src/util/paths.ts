// Cross-platform path helpers. Every getter reads env at call time so
// tests can swap HOME / XDG_CONFIG_HOME and have detectors honor the
// new values on the next probe.

import { homedir, platform } from "node:os";
import { join } from "node:path";

// `home()` is the root every detector + the install command pivots from
// when looking for harness config dirs. AGENTLOCK_DEV_HOME lets dev runs
// re-point that root at the repo's ./dev/ sandbox so detection scans
// ./dev/.claude, ./dev/.cursor, ./dev/.codex, ... instead of the user's
// real home — and the install command writes hooks into the same tree.
// Without it we'd silently target the developer's actual harness configs.
export function home(): string {
  return process.env.AGENTLOCK_DEV_HOME ?? process.env.HOME ?? homedir();
}

export function isMac(): boolean {
  return platform() === "darwin";
}

export function isLinux(): boolean {
  return platform() === "linux";
}

export function isWin(): boolean {
  return platform() === "win32";
}

/** ~/.config or platform equivalent. */
export function xdgConfigHome(): string {
  return process.env.XDG_CONFIG_HOME ?? join(home(), ".config");
}

/** Cross-platform "Application Support" / equivalent. */
export function appSupport(): string {
  if (isMac()) return join(home(), "Library", "Application Support");
  if (isWin()) return process.env.APPDATA ?? join(home(), "AppData", "Roaming");
  return xdgConfigHome();
}

/** Runtime state dir: ledger, session.key, pinned MCP pubkeys. */
export function agentlockHome(): string {
  return process.env.AGENTLOCK_HOME ?? join(appSupport(), "OpenAgentLock");
}

/** Stable wrapper-script home; survives package upgrades that move node_modules. */
export function binDir(): string {
  return join(agentlockHome(), "bin");
}

/** VS Code user dir (extension globalStorage lives under this). */
export function vscodeUserDir(): string | null {
  if (isMac()) return join(home(), "Library", "Application Support", "Code", "User");
  if (isLinux()) return join(xdgConfigHome(), "Code", "User");
  if (isWin()) return join(process.env.APPDATA ?? "", "Code", "User");
  return null;
}
