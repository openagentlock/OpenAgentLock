// Spawn the user's terminal editor on a tempfile and return the saved
// content. Used by the TUI's "add gate" / "edit gate" flows so users
// edit YAML in their preferred editor rather than a homegrown form.
//
// Caller is responsible for suspending the OpenTUI renderer before
// calling and resuming it after — this module deliberately knows
// nothing about OpenTUI so it stays unit-testable from a plain test.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface EditYAMLResult {
  // The full contents of the file after the editor exited and the user
  // saved. Empty string if the user wrote an empty file.
  content: string;
  // True if the content is byte-identical to the seed (user quit without
  // saving, or saved unchanged).
  unchanged: boolean;
}

// editYAMLInEditor seeds a tempfile with `seed`, spawns $EDITOR (or
// $VISUAL, or `vi`), waits for it to exit, and returns the post-edit
// content. The file is always cleaned up.
export async function editYAMLInEditor(
  seed: string,
  filenameHint = "agentlock-gate.yaml",
): Promise<EditYAMLResult> {
  const dir = mkdtempSync(join(tmpdir(), "agentlock-edit-"));
  const path = join(dir, filenameHint);
  writeFileSync(path, seed, { mode: 0o600 });
  try {
    await spawnEditor(path);
    const content = readFileSync(path, "utf8");
    return { content, unchanged: content === seed };
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup; tempfile lives in /tmp anyway
    }
  }
}

function spawnEditor(path: string): Promise<void> {
  // $VISUAL > $EDITOR > vi. Matches git, less, crontab convention. Most
  // shells set EDITOR but VISUAL only when the user wants something
  // different for full-screen editing — honour that distinction.
  const cmd = process.env.VISUAL || process.env.EDITOR || "vi";
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, [path], { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) {
        reject(new Error(`editor terminated by signal ${signal}`));
        return;
      }
      if (code !== 0) {
        reject(new Error(`editor exited with code ${code}`));
        return;
      }
      resolve();
    });
  });
}
