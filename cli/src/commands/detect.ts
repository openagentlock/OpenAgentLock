// `agentlock detect` — print a table of every detected agent harness.
// No TUI; plain stdout. Useful for scripts and CI.

import { detectAll } from "../detect/index.ts";

interface DetectOptions {
  json: boolean;
}

export async function runDetect(opts: DetectOptions): Promise<void> {
  const results = await detectAll();

  if (opts.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    return;
  }

  for (const r of results) {
    const mark = r.installed ? "●" : "○";
    process.stdout.write(`${mark} ${r.displayName}\n`);
    if (r.evidence.length === 0) {
      process.stdout.write(`    not detected\n`);
    } else {
      for (const e of r.evidence) process.stdout.write(`    ${e}\n`);
    }
    if (r.surfaces.length > 0) {
      process.stdout.write(`    surfaces: ${r.surfaces.join(", ")}\n`);
    }
    for (const n of r.notes) process.stdout.write(`    note: ${n}\n`);
    process.stdout.write("\n");
  }
}
