// GitHub Copilot for VS Code (extension), distinct from the standalone
// Copilot CLI. Detection is via the extension's globalStorage path under
// VS Code's user dir. Newer Copilot Chat builds (1.94+) ship MCP support
// so we report mcp-stdio + extension-only as candidate surfaces.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { vscodeUserDir } from "../util/paths.ts";
import { devStubStateForHarness } from "./agentlock-state.ts";
import type { DetectedScope, Detection, Detector } from "./types.ts";

const COPILOT_EXT_ID = "github.copilot";
const COPILOT_CHAT_EXT_ID = "github.copilot-chat";

export const vscodeCopilot: Detector = {
  id: "vscode-copilot",
  displayName: "GitHub Copilot (VS Code)",

  async detect(): Promise<Detection> {
    const userDir = vscodeUserDir();
    const evidence: string[] = [];
    const scopes: DetectedScope[] = [];

    if (!userDir) {
      return {
        id: this.id,
        displayName: this.displayName,
        installed: false,
        evidence: [],
        scopes,
        surfaces: ["extension-only"],
        notes: [],
      };
    }

    const copilotStorage = join(userDir, "globalStorage", COPILOT_EXT_ID);
    const chatStorage = join(userDir, "globalStorage", COPILOT_CHAT_EXT_ID);
    const settings = join(userDir, "settings.json");

    const copilotExists = existsSync(copilotStorage);
    const chatExists = existsSync(chatStorage);
    const settingsExists = existsSync(settings);

    if (copilotExists) evidence.push(`found ${copilotStorage}`);
    if (chatExists) evidence.push(`found ${chatStorage}`);
    if (settingsExists) evidence.push(`found ${settings}`);

    if (settingsExists) {
      scopes.push({ kind: "global", path: settings, exists: true });
    }

    const al = devStubStateForHarness(this.id);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: copilotExists || chatExists,
      evidence,
      scopes,
      surfaces: ["mcp-stdio", "extension-only"],
      notes: copilotExists || chatExists
        ? ["VS Code must be reloaded after Copilot Chat MCP changes."]
        : [],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
