// Detection tests. Seed a fake $HOME / $XDG_CONFIG_HOME under tmpdir,
// run the detector, assert what it returned. paths.ts reads env lazily,
// so each test sees a clean filesystem.
//
// Run: cd cli && bun test

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

import { claudeCode } from "../src/detect/claude-code.ts";
import { claudeDesktop, claudeDesktopConfigPath } from "../src/detect/claude-desktop.ts";
import { codex } from "../src/detect/codex.ts";
import { codexDesktop } from "../src/detect/codex-desktop.ts";
import { continueDev } from "../src/detect/continue-dev.ts";
import { cursor } from "../src/detect/cursor.ts";
import { gemini } from "../src/detect/gemini.ts";
import { opencode } from "../src/detect/opencode.ts";
import { vscodeCopilot } from "../src/detect/vscode-copilot.ts";
import { vscodeUserDir } from "../src/util/paths.ts";

let tmpHome: string;
let originalHome: string | undefined;
let originalXdg: string | undefined;
let originalCodexDesktopPaths: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(join(tmpdir(), "agentlock-test-"));
  originalHome = process.env.HOME;
  originalXdg = process.env.XDG_CONFIG_HOME;
  originalCodexDesktopPaths = process.env.AGENTLOCK_CODEX_DESKTOP_PATHS;
  process.env.HOME = tmpHome;
  process.env.XDG_CONFIG_HOME = join(tmpHome, ".config");
  process.env.AGENTLOCK_CODEX_DESKTOP_PATHS = [
    join(tmpHome, "Applications", "Codex.app"),
    join(tmpHome, "Library", "Application Support", "Codex"),
  ].join(delimiter);
  mkdirSync(process.env.XDG_CONFIG_HOME, { recursive: true });
});

afterEach(() => {
  if (originalHome !== undefined) process.env.HOME = originalHome;
  else delete process.env.HOME;
  if (originalXdg !== undefined) process.env.XDG_CONFIG_HOME = originalXdg;
  else delete process.env.XDG_CONFIG_HOME;
  if (originalCodexDesktopPaths !== undefined) {
    process.env.AGENTLOCK_CODEX_DESKTOP_PATHS = originalCodexDesktopPaths;
  } else {
    delete process.env.AGENTLOCK_CODEX_DESKTOP_PATHS;
  }
  rmSync(tmpHome, { recursive: true, force: true });
});

function touch(p: string, body = ""): void {
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, body);
}

describe("contract — every detector returns a well-formed Detection", () => {
  const detectors = [
    claudeCode,
    claudeDesktop,
    codex,
    codexDesktop,
    opencode,
    cursor,
    continueDev,
    gemini,
    vscodeCopilot,
  ];

  for (const d of detectors) {
    test(`${d.id} shape`, async () => {
      const r = await d.detect();
      expect(r.id).toBe(d.id);
      expect(r.displayName).toBe(d.displayName);
      expect(typeof r.installed).toBe("boolean");
      expect(Array.isArray(r.evidence)).toBe(true);
      expect(Array.isArray(r.scopes)).toBe(true);
      expect(Array.isArray(r.surfaces)).toBe(true);
      expect(Array.isArray(r.notes)).toBe(true);
      for (const s of r.scopes) {
        expect(["global", "project"]).toContain(s.kind);
        expect(typeof s.path).toBe("string");
        expect(typeof s.exists).toBe("boolean");
      }
    });
  }
});

describe("absent — installed=false on a clean home", () => {
  test("claude-code", async () => {
    const r = await claudeCode.detect();
    expect(r.installed).toBe(false);
    expect(r.evidence).toEqual([]);
  });

  test("claude-desktop", async () => {
    const r = await claudeDesktop.detect();
    expect(r.installed).toBe(false);
  });

  test("codex", async () => {
    const r = await codex.detect();
    expect(r.installed).toBe(false);
  });

  test("codex-desktop", async () => {
    const r = await codexDesktop.detect();
    expect(r.installed).toBe(false);
  });

  test("codex-desktop ignores shared ~/.codex files without Desktop app evidence", async () => {
    mkdirSync(join(tmpHome, ".codex"), { recursive: true });
    writeFileSync(join(tmpHome, ".codex", "config.toml"), "[features]\nhooks = true\n");
    writeFileSync(join(tmpHome, ".codex", "hooks.json"), "{}\n");
    const r = await codexDesktop.detect();
    expect(r.installed).toBe(false);
    expect(r.evidence.some((e) => e.includes(".codex/config.toml"))).toBe(true);
    expect(r.evidence.some((e) => e.includes(".codex/hooks.json"))).toBe(true);
  });

  test("opencode", async () => {
    const r = await opencode.detect();
    expect(r.installed).toBe(false);
  });

  test("continue", async () => {
    const r = await continueDev.detect();
    expect(r.installed).toBe(false);
  });

  test("gemini", async () => {
    const r = await gemini.detect();
    expect(r.installed).toBe(false);
  });

  test("vscode-copilot", async () => {
    const r = await vscodeCopilot.detect();
    expect(r.installed).toBe(false);
  });
});

describe("present — installed=true when expected files seeded", () => {
  test("claude-code with settings.json", async () => {
    touch(join(tmpHome, ".claude", "settings.json"), "{}");
    const r = await claudeCode.detect();
    expect(r.installed).toBe(true);
    expect(r.evidence.some((e) => e.includes(".claude/settings.json"))).toBe(true);
    expect(r.scopes[0]?.exists).toBe(true);
  });

  test("codex with config.toml", async () => {
    touch(join(tmpHome, ".codex", "config.toml"), "");
    const r = await codex.detect();
    expect(r.installed).toBe(true);
    expect(r.scopes[0]?.exists).toBe(true);
  });

  test("codex ignores legacy codex_hooks inside a TOML section", async () => {
    touch(
      join(tmpHome, ".codex", "config.toml"),
      "[tui.model_availability_nux]\ncodex_hooks = true\n",
    );
    const r = await codex.detect();
    expect(r.installed).toBe(true);
    expect(
      r.evidence.some((e) => e.includes("[features].hooks not set")),
    ).toBe(true);
  });

  test("codex recognizes [features] with an inline comment", async () => {
    touch(
      join(tmpHome, ".codex", "config.toml"),
      "[features] # Codex feature flags\nhooks = true\n",
    );
    const r = await codex.detect();
    expect(r.installed).toBe(true);
    expect(
      r.evidence.some((e) => e.includes("[features].hooks = true")),
    ).toBe(true);
  });

  test("codex-desktop with macOS app support directory", async () => {
    mkdirSync(join(tmpHome, "Library", "Application Support", "Codex"), {
      recursive: true,
    });
    const r = await codexDesktop.detect();
    expect(r.id).toBe("codex-desktop");
    expect(r.installed).toBe(true);
    expect(r.evidence.some((e) => e.includes("Application Support/Codex"))).toBe(
      true,
    );
    expect(r.scopes[0]?.path).toContain(".codex/config.toml");
    expect(r.scopes[0]?.exists).toBe(false);
  });

  test("opencode at xdg path", async () => {
    mkdirSync(join(process.env.XDG_CONFIG_HOME!, "opencode"), { recursive: true });
    const r = await opencode.detect();
    expect(r.installed).toBe(true);
  });

  test("continue with config.json", async () => {
    touch(join(tmpHome, ".continue", "config.json"), "{}");
    const r = await continueDev.detect();
    expect(r.installed).toBe(true);
    expect(r.scopes[0]?.exists).toBe(true);
  });

  test("gemini with ~/.gemini", async () => {
    mkdirSync(join(tmpHome, ".gemini"), { recursive: true });
    const r = await gemini.detect();
    expect(r.installed).toBe(true);
  });

  test("cursor reports agentlockInstalled from hooks.json", async () => {
    touch(
      join(tmpHome, ".cursor", "hooks.json"),
      JSON.stringify({
        version: 1,
        hooks: {
          preToolUse: [
            {
              _agentlock: true,
              command: "agentlock hook cursor pre-tool-use",
              env: { AGENTLOCK_DAEMON_URL: "http://127.0.0.1:7878" },
            },
          ],
        },
      }),
    );
    const r = await cursor.detect();
    expect(r.agentlockInstalled).toBe(true);
    expect(r.agentlockDaemonURL).toBe("http://127.0.0.1:7878");
  });

  test("gemini reports agentlockInstalled from settings.json", async () => {
    touch(
      join(tmpHome, ".gemini", "settings.json"),
      JSON.stringify({
        hooks: {
          BeforeTool: [
            {
              _agentlock: true,
              hooks: [
                {
                  type: "command",
                  command: "agentlock hook gemini pre-tool-use",
                  env: { AGENTLOCK_DAEMON_URL: "http://127.0.0.1:7878" },
                },
              ],
            },
          ],
        },
      }),
    );
    const r = await gemini.detect();
    expect(r.agentlockInstalled).toBe(true);
    expect(r.agentlockDaemonURL).toBe("http://127.0.0.1:7878");
  });

  test("vscode-copilot with extension globalStorage", async () => {
    const userDir = vscodeUserDir();
    if (!userDir) return; // platform without a vscode user dir mapping
    mkdirSync(join(userDir, "globalStorage", "github.copilot"), {
      recursive: true,
    });
    const r = await vscodeCopilot.detect();
    expect(r.installed).toBe(true);
  });
});

describe("contract details", () => {
  test("claude-code declares lifecycle-hooks surface", async () => {
    const r = await claudeCode.detect();
    expect(r.surfaces).toContain("lifecycle-hooks");
  });

  test("cursor declares mcp-stdio + extension-only surfaces", async () => {
    const r = await cursor.detect();
    expect(r.surfaces).toContain("mcp-stdio");
    expect(r.surfaces).toContain("extension-only");
  });

  // Claude Desktop's enforcement covers MCP tool calls (via the proxy),
  // not Anthropic's server-side cloud features. The detector must not
  // advertise lifecycle-hooks (we don't get a native PreToolUse) and
  // must surface the cloud-features-out-of-scope caveat in notes so
  // picker rows don't oversell coverage.
  test("claude-desktop surfaces MCP enforcement and out-of-scope caveat", async () => {
    const r = await claudeDesktop.detect();
    expect(r.surfaces).toContain("mcp-stdio");
    expect(r.surfaces).not.toContain("lifecycle-hooks");
    expect(
      r.notes.some(
        (n) =>
          n.includes("mcp-proxy") ||
          n.includes("out of scope") ||
          n.includes("cloud"),
      ),
    ).toBe(true);
  });

  test("claude-desktop detects when config dir exists", async () => {
    const dir = join(claudeDesktopConfigPath(), "..");
    mkdirSync(dir, { recursive: true });
    const r = await claudeDesktop.detect();
    expect(r.installed).toBe(true);
  });

  test("claude-desktop reports agentlockInstalled when our MCP entry is present", async () => {
    const cfg = claudeDesktopConfigPath();
    mkdirSync(join(cfg, ".."), { recursive: true });
    writeFileSync(
      cfg,
      JSON.stringify({
        mcpServers: {
          agentlock: {
            _agentlock: true,
            command: "agentlock",
            args: ["mcp-server"],
            env: { AGENTLOCK_DAEMON_URL: "http://127.0.0.1:7878" },
          },
        },
      }),
    );
    const r = await claudeDesktop.detect();
    expect(r.agentlockInstalled).toBe(true);
    expect(r.agentlockDaemonURL).toBe("http://127.0.0.1:7878");
  });
});

describe("registry", () => {
  test("detectAll returns one Detection per registered detector", async () => {
    const { ALL_DETECTORS, detectAll } = await import("../src/detect/index.ts");
    const results = await detectAll();
    expect(results.length).toBe(ALL_DETECTORS.length);
    const ids = new Set(results.map((r) => r.id));
    expect(ids.size).toBe(ALL_DETECTORS.length);
  });
});
