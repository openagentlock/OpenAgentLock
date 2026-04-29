import { existsSync } from "node:fs";
import { join } from "node:path";
import { vscodeUserDir } from "../util/paths.ts";
import { devStubStateForHarness } from "./agentlock-state.ts";
import type { Detector, Detection, DetectedScope } from "./types.ts";

const VSCODE_EXT_ID = "saoudrizwan.claude-dev";

export const cline: Detector = {
  id: "cline",
  displayName: "Cline (VSCode)",

  async detect(): Promise<Detection> {
    const userDir = vscodeUserDir();
    const evidence: string[] = [];
    const scopes: DetectedScope[] = [];

    if (!userDir) {
      return {
        id: this.id,
        displayName: this.displayName,
        installed: false,
        evidence: ["VSCode user dir not found"],
        scopes,
        surfaces: ["extension-only"],
        notes: [],
      };
    }

    const storage = join(userDir, "globalStorage", VSCODE_EXT_ID);
    const installed = existsSync(storage);
    if (installed) evidence.push(`found ${storage}`);

    const mcpSettings = join(storage, "settings", "cline_mcp_settings.json");
    if (existsSync(mcpSettings)) {
      evidence.push(`found ${mcpSettings}`);
      scopes.push({ kind: "global", path: mcpSettings, exists: true });
    }

    const al = devStubStateForHarness(this.id);

    return {
      id: this.id,
      displayName: this.displayName,
      installed,
      evidence,
      scopes,
      surfaces: ["mcp-stdio", "extension-only"],
      notes: installed
        ? ["VSCode must be reloaded after Cline MCP changes."]
        : [],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
