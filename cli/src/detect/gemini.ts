import { existsSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";
import { devStubStateForHarness } from "./agentlock-state.ts";
import type { Detector, Detection } from "./types.ts";

export const gemini: Detector = {
  id: "gemini",
  displayName: "Gemini CLI",

  async detect(): Promise<Detection> {
    const dir = join(home(), ".gemini");
    const dirExists = existsSync(dir);
    const evidence = dirExists ? [`found ${dir}`] : [];

    const al = devStubStateForHarness(this.id);

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
