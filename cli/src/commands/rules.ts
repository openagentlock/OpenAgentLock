// `agentlock rules ...` — community rules registry plumbing.
//
// Storage layout under $AGENTLOCK_HOME:
//   registries.json                   — [{ id, url, added_at }]
//   registries/<registry-id>/         — git clone of each registry repo
//
// Subcommands implemented here:
//   add <git-url> [--name <id>]
//   sources                              (list registries)
//   sync                                 (git pull each registry)
//   search [query]                       (grep across all rules)
//   install <ruleId | registryId:ruleId> [--replace]
//   uninstall <gateId>                   (DELETE /v1/policy/gates/{id})
//   remove <registry-id>                 (drop registry from disk)
//
// Daemon integration:
//   `install` POSTs the gate-block of the rule.yaml to /v1/policy/gates/yaml.
//   `uninstall` DELETEs the gate by id.
//
// The CLI never executes anything from the registry — it only reads
// rule.yaml files and ships their gate sub-blocks to the daemon via the
// existing CRUD surface. The trust boundary stays at the daemon.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, join } from "node:path";

import { agentlockHome } from "../util/paths";
import { apiClient } from "../util/api";

const UPSTREAM = {
  id: "openagentlock-rules",
  url: "https://github.com/openagentlock/rules.git",
};

interface RegistryEntry {
  id: string;
  url: string;
  added_at: string;
}

interface RegistriesFile {
  schema_version: 1;
  registries: RegistryEntry[];
}

interface RuleYAML {
  id: string;
  name?: string;
  description?: string;
  severity?: string;
  tags?: string[];
  gate?: Record<string, unknown>;
}

function registriesPath(): string {
  return join(agentlockHome(), "registries.json");
}

function registryDir(id: string): string {
  return join(agentlockHome(), "registries", id);
}

function readRegistries(): RegistriesFile {
  const p = registriesPath();
  if (!existsSync(p)) {
    return { schema_version: 1, registries: [] };
  }
  return JSON.parse(readFileSync(p, "utf8")) as RegistriesFile;
}

function writeRegistries(file: RegistriesFile): void {
  mkdirSync(agentlockHome(), { recursive: true });
  writeFileSync(registriesPath(), JSON.stringify(file, null, 2) + "\n", { mode: 0o600 });
}

function deriveRegistryId(url: string): string {
  // `https://github.com/foo/bar.git` -> `foo-bar`. Fall back to a
  // basename-with-dashes for any URL we can't parse.
  try {
    const u = new URL(url);
    const path = u.pathname.replace(/\.git$/, "").replace(/^\/+/, "");
    const slug = path.replace(/\//g, "-");
    return slug || basename(u.pathname);
  } catch {
    return basename(url, ".git").replace(/[^a-z0-9]+/gi, "-").toLowerCase();
  }
}

function git(args: string[], cwd?: string): { ok: boolean; stdout: string; stderr: string } {
  const r = spawnSync("git", args, {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  return {
    ok: r.status === 0,
    stdout: (r.stdout ?? "").trim(),
    stderr: (r.stderr ?? "").trim(),
  };
}

function ensureUpstreamRegistered(): void {
  const file = readRegistries();
  if (file.registries.some((r) => r.id === UPSTREAM.id)) return;
  file.registries.push({
    id: UPSTREAM.id,
    url: UPSTREAM.url,
    added_at: new Date().toISOString(),
  });
  writeRegistries(file);
}

function loadRule(yamlBody: string): RuleYAML {
  // Hand-rolled minimal YAML reader is too fragile for this; instead we
  // call into bun's bundled YAML parsing through a dynamic require to
  // avoid pulling another package. If `yaml` is unavailable we try
  // JSON-as-fallback (rule.yaml authors sometimes maintain JSON).
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml") as { parse(s: string): unknown };
    return yaml.parse(yamlBody) as RuleYAML;
  } catch {
    return JSON.parse(yamlBody) as RuleYAML;
  }
}

function dumpYAML(obj: unknown): string {
  // Same dependency as loadRule; bun ships `yaml` transitively via the
  // CLI's package.json. Fall back to JSON.stringify when missing — the
  // daemon happily round-trips JSON-as-YAML for our gate shape.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("yaml") as { stringify(o: unknown): string };
    return yaml.stringify(obj);
  } catch {
    return JSON.stringify(obj, null, 2);
  }
}

function listRulesIn(registryId: string): { ruleId: string; path: string; rule: RuleYAML }[] {
  const dir = registryDir(registryId);
  const rulesRoot = join(dir, "rules");
  if (!existsSync(rulesRoot)) return [];
  const out: { ruleId: string; path: string; rule: RuleYAML }[] = [];
  for (const entry of readdirSync(rulesRoot)) {
    const ruleDir = join(rulesRoot, entry);
    if (!statSync(ruleDir).isDirectory()) continue;
    const yamlPath = join(ruleDir, "rule.yaml");
    if (!existsSync(yamlPath)) continue;
    try {
      const rule = loadRule(readFileSync(yamlPath, "utf8"));
      if (typeof rule.id === "string" && rule.id) {
        out.push({ ruleId: rule.id, path: yamlPath, rule });
      }
    } catch {
      // Skip rules that fail to parse — the registry-side CI is the
      // place that tells the author about it; the consumer-side CLI
      // stays out of the way.
    }
  }
  return out;
}

interface ResolvedRule {
  registryId: string;
  ruleId: string;
  rule: RuleYAML;
  path: string;
}

function resolveRule(spec: string): ResolvedRule {
  const file = readRegistries();
  let targetRegistry: string | null = null;
  let targetRuleId = spec;
  if (spec.includes(":")) {
    const [reg, id] = spec.split(":", 2) as [string, string];
    targetRegistry = reg;
    targetRuleId = id;
  }
  const matches: ResolvedRule[] = [];
  for (const reg of file.registries) {
    if (targetRegistry && reg.id !== targetRegistry) continue;
    for (const r of listRulesIn(reg.id)) {
      if (r.ruleId === targetRuleId) {
        matches.push({
          registryId: reg.id,
          ruleId: r.ruleId,
          rule: r.rule,
          path: r.path,
        });
      }
    }
  }
  if (matches.length === 0) {
    throw new Error(
      `rule ${spec} not found in any synced registry. ` +
        `Run \`agentlock rules sync\` first, or check available rules with \`agentlock rules search\`.`,
    );
  }
  if (matches.length > 1) {
    const seen = matches.map((m) => `${m.registryId}:${m.ruleId}`).join(", ");
    throw new Error(
      `rule ${spec} is ambiguous (matches: ${seen}). Disambiguate with \`<registryId>:${targetRuleId}\`.`,
    );
  }
  return matches[0]!;
}

// ---------- subcommand handlers ----------

export interface RulesCommonOptions {
  url?: string;
  json?: boolean;
}

export async function runRulesAdd(opts: { url: string; name?: string } & RulesCommonOptions) {
  const file = readRegistries();
  const id = opts.name ?? deriveRegistryId(opts.url);
  if (file.registries.some((r) => r.id === id)) {
    throw new Error(`registry ${id} already added (use \`agentlock rules sync\` to refresh)`);
  }
  const dir = registryDir(id);
  mkdirSync(join(agentlockHome(), "registries"), { recursive: true });
  const r = git(["clone", "--depth", "1", opts.url, dir]);
  if (!r.ok) {
    throw new Error(`git clone failed: ${r.stderr}`);
  }
  file.registries.push({ id, url: opts.url, added_at: new Date().toISOString() });
  writeRegistries(file);
  if (opts.json) {
    process.stdout.write(JSON.stringify({ id, url: opts.url, dir }, null, 2) + "\n");
  } else {
    process.stdout.write(`registry added: ${id}\n  url: ${opts.url}\n  dir: ${dir}\n`);
  }
}

export async function runRulesSources(opts: RulesCommonOptions = {}) {
  ensureUpstreamRegistered();
  const file = readRegistries();
  if (opts.json) {
    process.stdout.write(JSON.stringify(file.registries, null, 2) + "\n");
    return;
  }
  if (file.registries.length === 0) {
    process.stdout.write("no registries configured (will register openagentlock-rules on first sync)\n");
    return;
  }
  for (const r of file.registries) {
    const dir = registryDir(r.id);
    const cloned = existsSync(dir) ? "cloned" : "not cloned (run sync)";
    process.stdout.write(`${r.id}\n  url:    ${r.url}\n  dir:    ${dir} (${cloned})\n  added:  ${r.added_at}\n`);
  }
}

export async function runRulesSync(opts: RulesCommonOptions = {}) {
  ensureUpstreamRegistered();
  const file = readRegistries();
  const results: { id: string; ok: boolean; message: string }[] = [];
  for (const r of file.registries) {
    const dir = registryDir(r.id);
    if (!existsSync(dir)) {
      const cl = git(["clone", "--depth", "1", r.url, dir]);
      results.push({ id: r.id, ok: cl.ok, message: cl.ok ? "cloned" : cl.stderr });
      continue;
    }
    const fetch = git(["-C", dir, "fetch", "--prune"]);
    if (!fetch.ok) {
      results.push({ id: r.id, ok: false, message: fetch.stderr });
      continue;
    }
    const reset = git(["-C", dir, "reset", "--hard", "origin/HEAD"]);
    results.push({
      id: r.id,
      ok: reset.ok,
      message: reset.ok ? "synced" : reset.stderr,
    });
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    return;
  }
  for (const r of results) {
    process.stdout.write(`${r.ok ? "✓" : "✘"} ${r.id}: ${r.message}\n`);
  }
}

export async function runRulesSearch(opts: { query?: string } & RulesCommonOptions) {
  ensureUpstreamRegistered();
  const file = readRegistries();
  const q = (opts.query ?? "").toLowerCase();
  const hits: { registry: string; rule: RuleYAML }[] = [];
  for (const reg of file.registries) {
    for (const r of listRulesIn(reg.id)) {
      const blob = [
        r.rule.id,
        r.rule.name ?? "",
        r.rule.description ?? "",
        ...(r.rule.tags ?? []),
      ]
        .join(" ")
        .toLowerCase();
      if (q === "" || blob.includes(q)) {
        hits.push({ registry: reg.id, rule: r.rule });
      }
    }
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify(hits, null, 2) + "\n");
    return;
  }
  if (hits.length === 0) {
    process.stdout.write(`no rules match "${q}" (try \`agentlock rules sync\` first)\n`);
    return;
  }
  for (const h of hits) {
    process.stdout.write(`${h.rule.id} (${h.registry})\n  ${h.rule.name ?? "(no name)"}\n  severity: ${h.rule.severity ?? "?"}\n`);
  }
}

export async function runRulesInstall(
  opts: { spec: string; replace?: boolean } & RulesCommonOptions,
) {
  const resolved = resolveRule(opts.spec);
  if (!resolved.rule.gate) {
    throw new Error(`rule ${resolved.ruleId} has no gate block — invalid registry rule`);
  }
  // Wire-shape the rule.yaml's `gate:` block as a top-level gate. The
  // daemon parses it as yamlRawGate; the rule id needs to live at the
  // top level of the gate block, not under it.
  const gateBlock = {
    id: resolved.rule.id,
    ...(resolved.rule.gate as Record<string, unknown>),
  };
  const yamlBody = dumpYAML(gateBlock);
  const client = apiClient(opts.url);
  const res = await client.installGateYAML(yamlBody, !!opts.replace);
  if (opts.json) {
    process.stdout.write(JSON.stringify({ ...res, registry: resolved.registryId }, null, 2) + "\n");
    return;
  }
  process.stdout.write(
    `installed ${resolved.ruleId} from registry ${resolved.registryId}.\n` +
      `  policy hash: ${res.hash}\n` +
      `  total gates: ${res.gates}\n`,
  );
}

export async function runRulesUninstall(opts: { id: string } & RulesCommonOptions) {
  const client = apiClient(opts.url);
  const res = await client.deleteGate(opts.id);
  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + "\n");
    return;
  }
  process.stdout.write(
    `uninstalled ${opts.id}.\n` +
      `  policy hash: ${res.hash}\n` +
      `  total gates: ${res.gates}\n`,
  );
}

export async function runRulesRemove(opts: { id: string } & RulesCommonOptions) {
  const file = readRegistries();
  const idx = file.registries.findIndex((r) => r.id === opts.id);
  if (idx === -1) {
    throw new Error(`registry ${opts.id} is not registered`);
  }
  file.registries.splice(idx, 1);
  writeRegistries(file);
  const dir = registryDir(opts.id);
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify({ removed: opts.id }, null, 2) + "\n");
  } else {
    process.stdout.write(`registry removed: ${opts.id}\n`);
  }
}
