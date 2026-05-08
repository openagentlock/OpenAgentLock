import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";
import { codexAgentlockState } from "./agentlock-state.ts";
import type { Detector, Detection, DetectedScope } from "./types.ts";

// OpenAI Codex CLI: ~/.codex/{config.toml, auth.json, hooks.json}.
// Lifecycle hooks (PreToolUse / PostToolUse / SessionStart / Stop) are
// available behind `[features].hooks = true` in config.toml. PreToolUse
// only fires for shell calls today — MCP coverage is tracked upstream.
export const codex: Detector = {
  id: "codex",
  displayName: "Codex CLI (OpenAI)",

  async detect(): Promise<Detection> {
    const dir = join(home(), ".codex");
    const configToml = join(dir, "config.toml");
    const authJson = join(dir, "auth.json");
    const hooksJson = join(dir, "hooks.json");

    const evidence: string[] = [];
    const dirExists = existsSync(dir);
    if (dirExists) evidence.push(`found ${dir}`);
    if (existsSync(configToml)) evidence.push(`found ${configToml}`);
    if (existsSync(authJson)) evidence.push(`found ${authJson}`);
    if (existsSync(hooksJson)) evidence.push(`found ${hooksJson}`);

    const flagEnabled = codexHooksFlagEnabled(configToml);
    if (existsSync(configToml)) {
      evidence.push(
        flagEnabled
          ? "config.toml: [features].hooks = true"
          : "config.toml: [features].hooks not set (install will enable it)",
      );
    }

    const scopes: DetectedScope[] = [
      { kind: "global", path: configToml, exists: existsSync(configToml) },
    ];

    const al = codexAgentlockState(hooksJson);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: dirExists,
      evidence,
      scopes,
      surfaces: ["lifecycle-hooks", "mcp-stdio"],
      notes: [
        "Codex hooks require `[features].hooks = true` in ~/.codex/config.toml.",
        "Bash-only today: PreToolUse does not fire for MCP tool calls (tracked upstream).",
      ],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};

// codexHooksFlagEnabled returns true when ~/.codex/config.toml enables
// current `[features].hooks` or the legacy top-level `codex_hooks` flag.
// We avoid pulling in a TOML parser for a single-key probe: the simple
// section-aware scan is good enough for detection.
function codexHooksFlagEnabled(configTomlPath: string): boolean {
  if (!existsSync(configTomlPath)) return false;
  let body: string;
  try {
    body = readFileSync(configTomlPath, "utf8");
  } catch {
    return false;
  }
  let inFeatures = false;
  let seenSection = false;
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      seenSection = true;
      const header = line.split("#", 1)[0]?.trim() ?? "";
      const name =
        header.startsWith("[") && header.endsWith("]")
          ? header.slice(1, -1).trim()
          : "";
      inFeatures = name === "features";
      continue;
    }
    if (inFeatures) {
      const m = line.match(/^hooks\s*=\s*(true|false)\b/);
      if (m) return m[1] === "true";
      continue;
    }
    if (!seenSection) {
      const legacy = line.match(/^codex_hooks\s*=\s*(true|false)\b/);
      if (legacy) return legacy[1] === "true";
    }
  }
  return false;
}
