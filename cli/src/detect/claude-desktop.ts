// Detector for Anthropic's standalone Claude Desktop app — distinct
// from Claude Code (the CLI/IDE harness). Different config dir, no
// PreToolUse / PostToolUse hook surface upstream.
//
// As of 2026-05, Claude Desktop's only documented extensibility surface
// is `mcpServers` entries in claude_desktop_config.json. Anthropic
// closed the hook-parity feature request (#45514) without shipping. We
// therefore install agentlock as an MCP server entry — that's the only
// honest write we can do here.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { appSupport } from "../util/paths.ts";
import { claudeDesktopAgentlockState } from "./agentlock-state.ts";
import type { Detector, Detection, DetectedScope } from "./types.ts";

// claudeDesktopConfigPath returns the platform-correct config path.
// macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
// Windows: %APPDATA%\Claude\claude_desktop_config.json
// Linux: not officially supported — fall through to xdgConfigHome via
// appSupport(), which gives a reasonable detection no-op (file won't
// exist on a Linux box) without crashing the registry.
export function claudeDesktopConfigPath(): string {
  return join(appSupport(), "Claude", "claude_desktop_config.json");
}

export const claudeDesktop: Detector = {
  id: "claude-desktop",
  displayName: "Claude Desktop",

  async detect(): Promise<Detection> {
    const configPath = claudeDesktopConfigPath();
    const dir = join(configPath, "..");
    const extensionsRegistry = join(dir, "extensions-installations.json");

    const evidence: string[] = [];
    const dirExists = existsSync(dir);
    const configExists = existsSync(configPath);
    if (dirExists) evidence.push(`found ${dir}`);
    if (configExists) evidence.push(`found ${configPath}`);

    // Count Desktop Extensions installed via Settings → Extensions UI.
    // This is the registry agentlock now wraps in addition to the
    // manual mcpServers path; surfacing the count tells the user up
    // front how much surface area they're hardening.
    const extensionCount = countInstalledExtensions(extensionsRegistry);
    if (extensionCount > 0) {
      evidence.push(
        `found ${extensionCount} Desktop Extension${extensionCount === 1 ? "" : "s"} (${extensionsRegistry})`,
      );
    }

    const scopes: DetectedScope[] = [
      { kind: "global", path: configPath, exists: configExists },
    ];

    const al = claudeDesktopAgentlockState(configPath);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: dirExists,
      evidence,
      scopes,
      // mcp-stdio only: Claude Desktop has no PreToolUse / PostToolUse
      // surface (anthropics/claude-code#45514, closed-as-duplicate, not
      // shipped). We cannot wire the same lifecycle-hooks path as Claude
      // Code; declaring it here would mislead the install picker.
      surfaces: ["mcp-stdio"],
      notes: dirExists
        ? [
            "Install wraps every MCP server entry (manual mcpServers + Desktop Extensions installed via Settings → Extensions UI) with `agentlock mcp-proxy` so each tools/call is gated by daemon policy. Manual mcpServers entries preserve originals under _agentlock_original; Desktop Extension bundle manifests stash originals under _meta.agentlock (MCPB v0.3+ schema slot).",
            "Anthropic auto-updates may overwrite the wrap on extension version bumps — re-run `agentlock install` after extension updates.",
            "Coverage is the MCP slice only: not gated are Computer Use, integrated terminal, native connectors (Slack/GCal), Cowork's non-MCP paths, and Anthropic cloud features. For full local enforcement, use Claude Code.",
          ]
        : [
            "Claude Desktop not detected. Selecting it will create the config dir on install.",
            "When Claude Desktop is in use, install wraps each MCP server (mcpServers + Desktop Extensions) — coverage is MCP-slice only (not Computer Use, terminal, connectors, or cloud features).",
          ],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};

// countInstalledExtensions parses extensions-installations.json and
// returns the number of installed Desktop Extensions. Returns 0 on any
// parse error or missing file — the count is informational; we don't
// want detection to fail loud on a malformed registry that the install
// pipeline will gracefully no-op past anyway.
function countInstalledExtensions(registryPath: string): number {
  if (!existsSync(registryPath)) return 0;
  try {
    const parsed = JSON.parse(readFileSync(registryPath, "utf8")) as {
      extensions?: Record<string, unknown>;
    };
    return Object.keys(parsed.extensions ?? {}).length;
  } catch {
    return 0;
  }
}
