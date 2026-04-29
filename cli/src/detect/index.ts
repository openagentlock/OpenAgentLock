// Detector registry. Add new harnesses here.

import { claudeCode } from "./claude-code.ts";
import { cline } from "./cline.ts";
import { codex } from "./codex.ts";
import { continueDev } from "./continue-dev.ts";
import { cursor } from "./cursor.ts";
import { gemini } from "./gemini.ts";
import { opencode } from "./opencode.ts";
import { vscodeCopilot } from "./vscode-copilot.ts";
import type { Detection, Detector } from "./types.ts";

// Registry of harnesses we can probe AND have a real integration surface
// for. Anything that's purely sandboxed or exposes no public hook / MCP
// path is left out — we don't ship dead picker rows.
export const ALL_DETECTORS: Detector[] = [
  claudeCode,
  codex,
  opencode,
  cursor,
  vscodeCopilot,
  cline,
  continueDev,
  gemini,
];

/** Run every detector in parallel. Order of results matches ALL_DETECTORS. */
export async function detectAll(): Promise<Detection[]> {
  return Promise.all(ALL_DETECTORS.map((d) => d.detect()));
}

export type { Detection, Detector } from "./types.ts";
