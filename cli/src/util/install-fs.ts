// Host-side filesystem helpers for install / uninstall. The daemon
// computes plan ops (plus per-harness uninstall strip ops) and the CLI
// runs them through this module — every disk write that used to live
// in the Go daemon now happens here, where $HOME is the user's real
// home and not /home/nonroot inside a container.

import { promises as fs } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { homedir } from "node:os";

import type { InstallFileOp, InstallUninstallOp } from "./api.ts";

export interface SafeTargetOpts {
  // Bypass the home-subtree check. Set when the caller is in dev mode
  // (--config-dir or AGENTLOCK_DEV_HOME) so source-tree test runs that
  // write into ./dev/.claude don't get rejected.
  bypass?: boolean;
}

// checkSafeTarget refuses paths that don't resolve under one of the
// real harness home subtrees. Mirrors the safety stance the daemon
// used to enforce; lives on the CLI side now because the daemon never
// touches host paths in the new flow.
export function checkSafeTarget(
  absPath: string,
  opts: SafeTargetOpts = {},
): void {
  if (opts.bypass) return;
  const home = homedir();
  const allowed = [".claude", ".codex", ".cursor"].map((d) =>
    resolve(home, d),
  );
  const target = resolve(absPath);
  for (const root of allowed) {
    if (target === root || target.startsWith(root + sep)) return;
  }
  throw new Error(
    `unsafe target: ${absPath} does not resolve under ~/.claude, ~/.codex, or ~/.cursor`,
  );
}

// readExistingFiles loads utf8 contents for each absolute path that
// exists; silently skips ENOENT so the caller can pass a list of
// "maybe present" paths and the daemon merges against whatever it
// gets back.
export async function readExistingFiles(
  paths: string[],
): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const p of paths) {
    try {
      out[p] = await fs.readFile(p, "utf8");
    } catch (err: unknown) {
      const code = (err as { code?: string }).code;
      if (code !== "ENOENT") throw err;
    }
  }
  return out;
}

interface ExecutedWrite {
  path: string;
  backupPath?: string;
  hadExisting: boolean;
}

// executeFileOps runs the daemon's plan against the host filesystem.
// Each "write" op:
//   1. mkdir -p on the parent
//   2. if backup_path is set AND the file exists, copy current bytes
//      to backup_path before overwriting
//   3. atomic write via tmp + rename
// On any mid-batch failure we roll back successful writes from their
// backups so the user is not left with a half-applied install.
export async function executeFileOps(ops: InstallFileOp[]): Promise<void> {
  const completed: ExecutedWrite[] = [];
  try {
    for (const op of ops) {
      if (op.op === "skip") continue;
      if (op.op === "remove") {
        try {
          await fs.unlink(op.path);
        } catch (err: unknown) {
          const code = (err as { code?: string }).code;
          if (code !== "ENOENT") throw err;
        }
        continue;
      }
      if (op.op === "write") {
        await fs.mkdir(dirname(op.path), { recursive: true });
        let hadExisting = false;
        if (op.backup_path) {
          try {
            const current = await fs.readFile(op.path);
            await fs.writeFile(op.backup_path, current, { mode: 0o600 });
            hadExisting = true;
          } catch (err: unknown) {
            const code = (err as { code?: string }).code;
            if (code !== "ENOENT") throw err;
          }
        }
        const tmp = op.path + ".agentlock-tmp";
        await fs.writeFile(tmp, op.content ?? "", { mode: 0o644 });
        await fs.rename(tmp, op.path);
        completed.push({
          path: op.path,
          backupPath: op.backup_path,
          hadExisting,
        });
        continue;
      }
      throw new Error(`unsupported op kind: ${op.op}`);
    }
  } catch (err) {
    // Roll back completed writes from their backups, newest-first.
    for (const w of completed.reverse()) {
      try {
        if (w.hadExisting && w.backupPath) {
          const backup = await fs.readFile(w.backupPath);
          await fs.writeFile(w.path, backup);
        } else if (!w.hadExisting) {
          await fs.unlink(w.path);
        }
      } catch {
        // best-effort
      }
    }
    throw err;
  }
}

// executeUninstallOps runs the daemon's strip / remove ops on the host.
// Strip ops carry the post-strip file contents in op.content; missing
// content means the file had no agentlock entries to remove and we
// leave it untouched.
export async function executeUninstallOps(
  ops: InstallUninstallOp[],
): Promise<void> {
  for (const op of ops) {
    if (op.error) continue; // daemon-side error; surfaced separately
    if (op.op === "skip") continue;
    if (op.op === "remove") {
      try {
        await fs.unlink(op.path);
      } catch (err: unknown) {
        const code = (err as { code?: string }).code;
        if (code !== "ENOENT") throw err;
      }
      continue;
    }
    if (op.op === "strip") {
      // No content means nothing to strip — file was missing or had
      // no agentlock entries. Leave it untouched.
      if (!op.content) continue;
      const tmp = op.path + ".agentlock-tmp";
      await fs.writeFile(tmp, op.content, { mode: 0o644 });
      await fs.rename(tmp, op.path);
    }
  }
}
