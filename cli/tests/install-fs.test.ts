// Unit tests for the host-side filesystem helpers in
// cli/src/util/install-fs.ts. These exercise the path the daemon used
// to own — atomic writes, backups, rollback, ENOENT idempotency — and
// the safety check that refuses targets outside ~/.claude / ~/.codex /
// ~/.cursor.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

import {
  checkSafeTarget,
  executeFileOps,
  executeUninstallOps,
  readExistingFiles,
} from "../src/util/install-fs.ts";
import type { InstallFileOp, InstallUninstallOp } from "../src/util/api.ts";

let workdir: string;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), "agentlock-install-fs-"));
});

afterEach(async () => {
  await fs.rm(workdir, { recursive: true, force: true });
});

async function exists(p: string): Promise<boolean> {
  try {
    await fs.stat(p);
    return true;
  } catch {
    return false;
  }
}

describe("executeFileOps - write", () => {
  test("creates a fresh file when no backup_path is supplied", async () => {
    const target = join(workdir, "fresh.json");
    const op: InstallFileOp = {
      op: "write",
      path: target,
      content: '{"hello":true}',
    };
    await executeFileOps([op]);
    const got = await fs.readFile(target, "utf8");
    expect(got).toBe('{"hello":true}');
  });

  test("creates parent directories recursively", async () => {
    const target = join(workdir, "nested", "dir", "settings.json");
    await executeFileOps([
      { op: "write", path: target, content: "{}" },
    ]);
    expect(await exists(target)).toBe(true);
  });

  test("with backup_path set, overwriting an existing file moves old bytes to backup", async () => {
    const target = join(workdir, "settings.json");
    const backup = join(workdir, "settings.json.bak");
    await fs.writeFile(target, "OLD");
    await executeFileOps([
      {
        op: "write",
        path: target,
        content: "NEW",
        backup_path: backup,
      },
    ]);
    expect(await fs.readFile(target, "utf8")).toBe("NEW");
    expect(await fs.readFile(backup, "utf8")).toBe("OLD");
  });

  test("with backup_path set but no existing file, write succeeds and no backup is created", async () => {
    const target = join(workdir, "settings.json");
    const backup = join(workdir, "settings.json.bak");
    await executeFileOps([
      {
        op: "write",
        path: target,
        content: "NEW",
        backup_path: backup,
      },
    ]);
    expect(await fs.readFile(target, "utf8")).toBe("NEW");
    expect(await exists(backup)).toBe(false);
  });
});

describe("executeFileOps - remove", () => {
  test("unlinks the file", async () => {
    const target = join(workdir, "doomed");
    await fs.writeFile(target, "x");
    await executeFileOps([{ op: "remove", path: target, content: "" }]);
    expect(await exists(target)).toBe(false);
  });

  test("is idempotent on ENOENT", async () => {
    const target = join(workdir, "never-existed");
    await executeFileOps([{ op: "remove", path: target, content: "" }]);
    // Did not throw; that's the assertion.
  });
});

describe("executeFileOps - skip", () => {
  test("makes no filesystem changes", async () => {
    const target = join(workdir, "untouched");
    await executeFileOps([{ op: "skip", path: target, content: "" }]);
    expect(await exists(target)).toBe(false);
  });
});

describe("executeFileOps - rollback on mid-batch failure", () => {
  test("restores completed write from backup when a later op fails", async () => {
    const a = join(workdir, "a.json");
    const b = join(workdir, "b.json");
    const aBackup = join(workdir, "a.json.bak");
    await fs.writeFile(a, "A_OLD");
    // Force the second op to fail by giving it an unsupported op kind.
    const ops: InstallFileOp[] = [
      { op: "write", path: a, content: "A_NEW", backup_path: aBackup },
      { op: "boom" as unknown as string, path: b, content: "x" } as InstallFileOp,
    ];
    let threw = false;
    try {
      await executeFileOps(ops);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    // a.json should be back to A_OLD (rolled back from backup).
    expect(await fs.readFile(a, "utf8")).toBe("A_OLD");
  });

  test("removes successful fresh-write when later op fails", async () => {
    const a = join(workdir, "fresh.json");
    const b = join(workdir, "second.json");
    const ops: InstallFileOp[] = [
      { op: "write", path: a, content: "A" },
      { op: "boom" as unknown as string, path: b, content: "x" } as InstallFileOp,
    ];
    let threw = false;
    try {
      await executeFileOps(ops);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    // a.json should not exist anymore (no backup → unlink on rollback).
    expect(await exists(a)).toBe(false);
  });
});

describe("executeUninstallOps", () => {
  test("strip writes content back to the file", async () => {
    const target = join(workdir, "settings.json");
    await fs.writeFile(target, '{"old":true,"hooks":{"_agentlock":[]}}');
    const op: InstallUninstallOp = {
      op: "strip",
      path: target,
      entries_removed: 1,
      content: '{"old":true}',
    };
    await executeUninstallOps([op]);
    expect(await fs.readFile(target, "utf8")).toBe('{"old":true}');
  });

  test("strip with empty content leaves the file untouched", async () => {
    const target = join(workdir, "settings.json");
    await fs.writeFile(target, "ORIGINAL");
    const op: InstallUninstallOp = {
      op: "strip",
      path: target,
      entries_removed: 0,
      content: "",
    };
    await executeUninstallOps([op]);
    expect(await fs.readFile(target, "utf8")).toBe("ORIGINAL");
  });

  test("remove unlinks the file", async () => {
    const target = join(workdir, "marker");
    await fs.writeFile(target, "x");
    await executeUninstallOps([
      { op: "remove", path: target, entries_removed: 1 },
    ]);
    expect(await exists(target)).toBe(false);
  });

  test("remove is idempotent on ENOENT", async () => {
    const target = join(workdir, "never");
    await executeUninstallOps([
      { op: "remove", path: target, entries_removed: 0 },
    ]);
  });

  test("skip does nothing", async () => {
    await executeUninstallOps([
      { op: "skip", path: "ignored", entries_removed: 0 },
    ]);
  });

  test("daemon-side error entries are skipped on the CLI side", async () => {
    const target = join(workdir, "settings.json");
    await fs.writeFile(target, "ORIGINAL");
    await executeUninstallOps([
      {
        op: "strip",
        path: target,
        entries_removed: 0,
        content: "WOULD_OVERWRITE",
        error: "parse error",
      },
    ]);
    // Despite content being set, error means CLI skips the write.
    expect(await fs.readFile(target, "utf8")).toBe("ORIGINAL");
  });
});

describe("checkSafeTarget", () => {
  const home = homedir();

  test("accepts paths under ~/.claude", () => {
    expect(() =>
      checkSafeTarget(resolve(home, ".claude", "settings.json")),
    ).not.toThrow();
  });

  test("accepts paths under ~/.codex", () => {
    expect(() =>
      checkSafeTarget(resolve(home, ".codex", "hooks.json")),
    ).not.toThrow();
  });

  test("accepts paths under ~/.cursor", () => {
    expect(() =>
      checkSafeTarget(resolve(home, ".cursor", "hooks.json")),
    ).not.toThrow();
  });

  test("accepts the .claude directory itself", () => {
    expect(() => checkSafeTarget(resolve(home, ".claude"))).not.toThrow();
  });

  test("rejects paths elsewhere in $HOME", () => {
    expect(() =>
      checkSafeTarget(resolve(home, ".bashrc")),
    ).toThrow(/unsafe target/);
  });

  test("rejects paths outside $HOME", () => {
    expect(() => checkSafeTarget("/etc/passwd")).toThrow(/unsafe target/);
  });

  test("rejects sibling-prefix attempts (~/.claude.evil)", () => {
    expect(() =>
      checkSafeTarget(home + sep + ".claude.evil"),
    ).toThrow(/unsafe target/);
  });

  test("with bypass: true allows arbitrary paths", () => {
    expect(() =>
      checkSafeTarget("/tmp/anywhere", { bypass: true }),
    ).not.toThrow();
    expect(() =>
      checkSafeTarget("/etc/passwd", { bypass: true }),
    ).not.toThrow();
  });
});

describe("readExistingFiles", () => {
  test("returns contents for files that exist, omits absent ones", async () => {
    const a = join(workdir, "a.txt");
    const b = join(workdir, "b.txt");
    const c = join(workdir, "missing.txt");
    await fs.writeFile(a, "AAA");
    await fs.writeFile(b, "BBB");
    const got = await readExistingFiles([a, b, c]);
    expect(got[a]).toBe("AAA");
    expect(got[b]).toBe("BBB");
    expect(c in got).toBe(false);
  });

  test("returns an empty map when no inputs", async () => {
    const got = await readExistingFiles([]);
    expect(Object.keys(got)).toHaveLength(0);
  });
});
