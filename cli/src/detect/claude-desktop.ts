// Detector for Anthropic's standalone Claude Desktop app — distinct
// from Claude Code (the CLI/IDE harness). Different config dir, no
// PreToolUse / PostToolUse hook surface upstream.
//
// As of 2026-05, Claude Desktop's only documented extensibility surface
// is `mcpServers` entries in claude_desktop_config.json. Anthropic
// closed the hook-parity feature request (#45514) without shipping. We
// therefore install agentlock as an MCP server entry — that's the only
// honest write we can do here.

import { existsSync } from "node:fs";
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

    const evidence: string[] = [];
    const dirExists = existsSync(dir);
    const configExists = existsSync(configPath);
    if (dirExists) evidence.push(`found ${dir}`);
    if (configExists) evidence.push(`found ${configPath}`);

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
            "Install wraps every MCP server entry with `agentlock mcp-proxy` so each tools/call is gated by daemon policy. Originals preserved under _agentlock_original for clean uninstall.",
            "Coverage is the MCP slice only: not gated are Computer Use, integrated terminal, native connectors (Slack/GCal), Cowork's non-MCP paths, and Anthropic cloud features. For full local enforcement, use Claude Code.",
          ]
        : [
            "Claude Desktop not detected. Selecting it will create the config dir on install.",
            "When Claude Desktop is in use, install wraps each MCP server — coverage is MCP-slice only (not Computer Use, terminal, connectors, or cloud features).",
          ],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
