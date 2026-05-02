import { existsSync } from "node:fs";
import { join } from "node:path";
import { appSupport, home, isMac } from "../util/paths.ts";
import { devStubStateForHarness } from "./agentlock-state.ts";
import type { Detector, Detection, DetectedScope } from "./types.ts";

function editorUserDir(): string {
  if (isMac()) return join(appSupport(), "Cursor", "User");
  return join(appSupport(), "Cursor", "User");
}

export const cursor: Detector = {
  id: "cursor",
  displayName: "Cursor",

  async detect(): Promise<Detection> {
    const cursorDir = join(home(), ".cursor");
    const globalMcp = join(cursorDir, "mcp.json");
    const globalHooks = join(cursorDir, "hooks.json");
    const userDir = editorUserDir();

    const evidence: string[] = [];
    const dotDir = existsSync(cursorDir);
    const userExists = existsSync(userDir);
    if (dotDir) evidence.push(`found ${cursorDir}`);
    if (userExists) evidence.push(`found ${userDir}`);
    if (existsSync(globalMcp)) evidence.push(`found ${globalMcp}`);
    if (existsSync(globalHooks)) evidence.push(`found ${globalHooks}`);

    const scopes: DetectedScope[] = [
      { kind: "global", path: globalMcp, exists: existsSync(globalMcp) },
    ];

    const al = devStubStateForHarness(this.id);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: dotDir || userExists,
      evidence,
      scopes,
      // lifecycle-hooks must be index 0 so the picker's `none-known`
      // gate (which reads surfaces[0]) doesn't disable the row.
      surfaces: ["lifecycle-hooks", "mcp-stdio", "extension-only"],
      notes: [
        "Cursor ≥1.7 hooks live at ~/.cursor/hooks.json (camelCase event keys).",
        "Cursor must be relaunched after hook config changes.",
      ],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
