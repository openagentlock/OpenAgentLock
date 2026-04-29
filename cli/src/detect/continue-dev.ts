import { existsSync } from "node:fs";
import { join } from "node:path";
import { home } from "../util/paths.ts";
import { devStubStateForHarness } from "./agentlock-state.ts";
import type { Detector, Detection } from "./types.ts";

export const continueDev: Detector = {
  id: "continue",
  displayName: "Continue.dev",

  async detect(): Promise<Detection> {
    const dir = join(home(), ".continue");
    const config = join(dir, "config.json");
    const evidence: string[] = [];
    const dirExists = existsSync(dir);
    if (dirExists) evidence.push(`found ${dir}`);
    if (existsSync(config)) evidence.push(`found ${config}`);

    const al = devStubStateForHarness(this.id);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: dirExists,
      evidence,
      scopes: [{ kind: "global", path: config, exists: existsSync(config) }],
      surfaces: ["mcp-stdio", "extension-only"],
      notes: [],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
