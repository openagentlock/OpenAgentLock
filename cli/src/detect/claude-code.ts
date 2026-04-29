import { existsSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";
import { claudeAgentlockState } from "./agentlock-state.ts";
import type { Detector, Detection, DetectedScope } from "./types.ts";

export const claudeCode: Detector = {
  id: "claude-code",
  displayName: "Claude Code",

  async detect(): Promise<Detection> {
    const globalDir = join(home(), ".claude");
    const settings = join(globalDir, "settings.json");

    const evidence: string[] = [];
    const dirExists = existsSync(globalDir);
    const settingsExists = existsSync(settings);
    if (dirExists) evidence.push(`found ${globalDir}`);
    if (settingsExists) evidence.push(`found ${settings}`);

    const scopes: DetectedScope[] = [
      { kind: "global", path: settings, exists: settingsExists },
    ];

    const al = claudeAgentlockState(settings);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: dirExists,
      evidence,
      scopes,
      surfaces: ["lifecycle-hooks", "mcp-stdio"],
      notes: dirExists
        ? []
        : [
            "Claude Code not detected. Selecting it will create the config dir on install.",
          ],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
