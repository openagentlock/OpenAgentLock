import { existsSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";
import { geminiAgentlockState } from "./agentlock-state.ts";
import type { Detector, Detection } from "./types.ts";

export const gemini: Detector = {
  id: "gemini",
  displayName: "Gemini CLI",

  async detect(): Promise<Detection> {
    const dir = join(home(), ".gemini");
    const settingsPath = join(dir, "settings.json");
    const dirExists = existsSync(dir);
    const evidence = dirExists ? [`found ${dir}`] : [];
    if (existsSync(settingsPath)) evidence.push(`found ${settingsPath}`);

    const al = geminiAgentlockState(settingsPath);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: dirExists,
      evidence,
      scopes: [{ kind: "global", path: dir, exists: dirExists }],
      surfaces: ["mcp-stdio"],
      notes: [],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
