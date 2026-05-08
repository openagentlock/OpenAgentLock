import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { appSupport, home, isMac, isWin, xdgConfigHome } from "../util/paths.ts";
import { codexAgentlockState } from "./agentlock-state.ts";
import type { Detection, DetectedScope, Detector } from "./types.ts";

function desktopAppCandidates(): string[] {
  if (process.env.AGENTLOCK_CODEX_DESKTOP_PATHS) {
    return process.env.AGENTLOCK_CODEX_DESKTOP_PATHS.split(delimiter)
      .map((p) => p.trim())
      .filter(Boolean);
  }
  if (isMac()) {
    return [
      "/Applications/Codex.app",
      join(home(), "Applications", "Codex.app"),
      join(appSupport(), "Codex"),
    ];
  }
  if (isWin()) {
    return [
      join(process.env.LOCALAPPDATA ?? join(home(), "AppData", "Local"), "Programs", "Codex"),
      join(appSupport(), "Codex"),
    ];
  }
  return [
    join(xdgConfigHome(), "Codex"),
    join(home(), ".local", "share", "Codex"),
  ];
}

// OpenAI Codex Desktop is a separate harness from the Codex CLI in the
// picker. Current Desktop builds share ~/.codex/{config.toml,hooks.json}
// with the CLI, so the installer has to treat CLI-only, Desktop-only,
// and shared installs deliberately.
export const codexDesktop: Detector = {
  id: "codex-desktop",
  displayName: "Codex Desktop (OpenAI)",

  async detect(): Promise<Detection> {
    const candidates = desktopAppCandidates();
    const desktopEvidence = candidates
      .filter((p) => existsSync(p))
      .map((p) => `found ${p}`);
    const evidence = [...desktopEvidence];

    const codexDir = join(home(), ".codex");
    const configToml = join(codexDir, "config.toml");
    const hooksJson = join(codexDir, "hooks.json");
    if (existsSync(configToml)) evidence.push(`found shared ${configToml}`);
    if (existsSync(hooksJson)) evidence.push(`found shared ${hooksJson}`);

    const scopes: DetectedScope[] = [
      { kind: "global", path: configToml, exists: existsSync(configToml) },
    ];

    const al = codexAgentlockState(hooksJson);

    return {
      id: this.id,
      displayName: this.displayName,
      installed: desktopEvidence.length > 0,
      evidence,
      scopes,
      surfaces: ["lifecycle-hooks", "mcp-stdio"],
      notes: [
        "Codex Desktop is detected separately from Codex CLI.",
        "Codex Desktop shares ~/.codex/hooks.json with Codex CLI; selecting both installs a shared routing shim.",
      ],
      agentlockInstalled: al.installed,
      agentlockDaemonURL: al.daemonURL,
    };
  },
};
