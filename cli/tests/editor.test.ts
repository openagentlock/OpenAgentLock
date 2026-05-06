// Unit tests for the $EDITOR helper used by the TUI's gate add/edit
// flows. Drives a fake editor by setting EDITOR to a small bash script
// that mutates the seed file in known ways. Hermetic, no real editor.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { editYAMLInEditor } from "../src/util/editor.ts";

let dir = "";
const origEditor = process.env.EDITOR;
const origVisual = process.env.VISUAL;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentlock-editor-test-"));
  // VISUAL takes precedence over EDITOR in the helper. Clear it so the
  // tests' EDITOR shim is the only thing in play.
  delete process.env.VISUAL;
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  if (origEditor === undefined) delete process.env.EDITOR;
  else process.env.EDITOR = origEditor;
  if (origVisual === undefined) delete process.env.VISUAL;
  else process.env.VISUAL = origVisual;
});

function makeShim(body: string): string {
  const path = join(dir, "fake-editor.sh");
  writeFileSync(path, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

describe("editYAMLInEditor", () => {
  test("returns post-save content and unchanged=false when editor mutates the file", async () => {
    process.env.EDITOR = makeShim('echo "id: appended" >> "$1"');
    const r = await editYAMLInEditor("id: original\n", "test.yaml");
    expect(r.unchanged).toBe(false);
    expect(r.content).toContain("id: original");
    expect(r.content).toContain("id: appended");
  });

  test("returns unchanged=true when the editor leaves the file alone", async () => {
    process.env.EDITOR = makeShim("true"); // touch nothing
    const r = await editYAMLInEditor("id: leave-me\n", "test.yaml");
    expect(r.unchanged).toBe(true);
    expect(r.content).toBe("id: leave-me\n");
  });

  test("rejects when the editor exits non-zero", async () => {
    process.env.EDITOR = makeShim("exit 7");
    await expect(editYAMLInEditor("seed", "test.yaml")).rejects.toThrow(/code 7/);
  });

  test("falls back to vi when neither EDITOR nor VISUAL is set", async () => {
    // Can't actually invoke vi in an automated test, so substitute a
    // shim named "vi" on a PATH we control to verify resolution order.
    delete process.env.EDITOR;
    delete process.env.VISUAL;
    const viShim = makeShim('echo "from-vi-shim" >> "$1"');
    // Rename to literal "vi" and prepend its dir to PATH.
    const viPath = join(dir, "vi");
    writeFileSync(viPath, `#!/usr/bin/env bash\necho "from-vi-shim" >> "$1"\n`, {
      mode: 0o700,
    });
    chmodSync(viPath, 0o700);
    const origPath = process.env.PATH;
    process.env.PATH = `${dir}:${origPath}`;
    try {
      const r = await editYAMLInEditor("seed\n", "test.yaml");
      expect(r.content).toContain("from-vi-shim");
    } finally {
      process.env.PATH = origPath;
    }
    // referenced so lint doesn't trip
    expect(viShim).toContain(dir);
  });

  test("VISUAL takes precedence over EDITOR", async () => {
    process.env.EDITOR = makeShim('echo "from-editor" >> "$1"');
    process.env.VISUAL = makeShim('echo "from-visual" >> "$1"');
    const r = await editYAMLInEditor("seed\n", "test.yaml");
    expect(r.content).toContain("from-visual");
    expect(r.content).not.toContain("from-editor");
  });
});
