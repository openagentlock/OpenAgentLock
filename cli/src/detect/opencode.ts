import { existsSync } from "node:fs";
import { join } from "node:path";
import { home, xdgConfigHome } from "../util/paths.ts";
import { devStubStateForHarness } from "./agentlock-state.ts";
import type { Detector, Detection, DetectedScope } from "./types.ts";

// OpenCode: ~/.config/opencode/ and ~/.opencode/
export const opencode: Detector = {
  id: "opencode",
  displayName: "OpenCode",

  async detect(): Promise<Detection> {
    const candidates = [join(xdgConfigHome(), "opencode"), join(home(), ".opencode")];
    const evidence: string[] = [];
    const present = candidates.filter((p) => existsSync(p));
    for (const p of present) evidence.push(`found ${p}`);

    const scopes: DetectedScope[] = present.map((p) => ({
      kind: "global",
      path: join(p, "config.json"),
      exists: existsSync(join(p, "config.json")),
    }));

    const al = devStubStateForHarness(this.id);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: present.length > 0,
      evidence,
      scopes,
      surfaces: ["mcp-stdio"],
      notes: [],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
