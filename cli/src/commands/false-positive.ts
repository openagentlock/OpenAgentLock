import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

import { apiClient, type FalsePositiveCaseResponse } from "../util/api";

export interface FalsePositiveCreateOptions {
  seq: number;
  url?: string;
  out?: string;
  includeRaw?: boolean;
  json?: boolean;
}

export interface FalsePositiveApplyOptions {
  caseDir: string;
  url?: string;
  note?: string;
  json?: boolean;
}

export interface FalsePositiveRulesPatchOptions {
  caseDir: string;
  rulesRepo: string;
  json?: boolean;
}

export async function runFalsePositiveCreate(opts: FalsePositiveCreateOptions) {
  const client = apiClient(opts.url);
  const c = await client.falsePositiveCase(opts.seq, opts.includeRaw);
  const out = resolve(opts.out ?? `agentlock-false-positive-${c.event.seq}`);
  mkdirSync(out, { recursive: true });

  const replacement = defaultReplacementYAML(c);
  writeFileSync(join(out, "case.json"), JSON.stringify(c, null, 2) + "\n", { mode: 0o600 });
  writeFileSync(join(out, "replacement.yaml"), replacement, { mode: 0o600 });
  writeFileSync(join(out, "README.md"), caseReadme(c), { mode: 0o600 });

  if (opts.json) {
    process.stdout.write(JSON.stringify({ dir: out, seq: c.event.seq, raw: !!opts.includeRaw }, null, 2) + "\n");
    return;
  }
  process.stdout.write(
    `false-positive case written: ${out}\n` +
      `  event: #${c.event.seq} ${c.event.source} ${c.event.tool ?? ""}\n` +
      `  rule: ${c.event.rule_id}\n` +
      `  raw event data: ${opts.includeRaw ? "included" : "redacted only"}\n` +
      `\nEdit replacement.yaml, then run:\n` +
      `  agentlock false-positive apply ${out}\n`,
  );
}

export async function runFalsePositiveApply(opts: FalsePositiveApplyOptions) {
  const dir = resolve(opts.caseDir);
  const c = readCase(dir);
  const replacement = readFileSync(join(dir, "replacement.yaml"), "utf8");
  const client = apiClient(opts.url);
  const validation = await client.falsePositiveValidate({ case: c, replacement_yaml: replacement });
  if (!validation.ok) {
    const errors = validation.errors?.map((e) => `  - ${e}`).join("\n") ?? "  - validation failed";
    throw new Error(`replacement did not validate:\n${errors}`);
  }
  const applied = await client.falsePositiveApply({
    case: c,
    replacement_yaml: replacement,
    note: opts.note,
  });
  if (opts.json) {
    process.stdout.write(JSON.stringify(applied, null, 2) + "\n");
    return;
  }
  process.stdout.write(
    `false-positive fix applied.\n` +
      `  disabled: ${applied.disabled_id}\n` +
      `  replacement: ${applied.replacement_id}\n` +
      `  policy: ${applied.hash}\n` +
      `  reload sessions to pick up the new policy.\n`,
  );
}

export async function runFalsePositiveRulesPatch(opts: FalsePositiveRulesPatchOptions) {
  const dir = resolve(opts.caseDir);
  const repo = resolve(opts.rulesRepo);
  if (!existsSync(repo) || !statSync(repo).isDirectory()) {
    throw new Error(`rules repo not found: ${repo}`);
  }
  const c = readCase(dir);
  const replacement = readFileSync(join(dir, "replacement.yaml"), "utf8");
  const slug = sanitizePathPart(c.event.rule_id);
  const out = join(repo, "drafts", `false-positive-${slug}-${c.event.seq}`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "case.redacted.json"), JSON.stringify(c, null, 2) + "\n", { mode: 0o600 });
  writeFileSync(join(out, "replacement.rule.yaml"), replacement, { mode: 0o600 });
  writeFileSync(join(out, "REPORT.md"), rulesPatchReport(c), { mode: 0o600 });
  if (opts.json) {
    process.stdout.write(JSON.stringify({ dir: out }, null, 2) + "\n");
    return;
  }
  process.stdout.write(`rules patch draft written: ${out}\n`);
}

function readCase(dir: string): FalsePositiveCaseResponse {
  const p = join(dir, "case.json");
  if (!existsSync(p)) {
    throw new Error(`case.json not found in ${dir}`);
  }
  return JSON.parse(readFileSync(p, "utf8")) as FalsePositiveCaseResponse;
}

function defaultReplacementYAML(c: FalsePositiveCaseResponse): string {
  const tool = c.event.tool ? `  tool: ${quoteYAML(c.event.tool)}\n` : "";
  return `id: ${c.event.rule_id}.replacement
match:
${tool}  any_command_regex:
    - '(?!)'
evaluate:
  - kind: always
    action: deny
`;
}

function caseReadme(c: FalsePositiveCaseResponse): string {
  return `# AgentLock false-positive case

Event: #${c.event.seq}
Source: ${c.event.source}
Rule: ${c.event.rule_id}

Files:
- \`case.json\`: redacted case bundle
- \`replacement.yaml\`: replacement gate draft

Edit \`replacement.yaml\` so it blocks the malicious shape without denying this event, then run:

\`\`\`bash
agentlock false-positive apply .
\`\`\`
`;
}

function rulesPatchReport(c: FalsePositiveCaseResponse): string {
  return `# False positive report

Rule: \`${c.event.rule_id}\`
Event seq: \`${c.event.seq}\`
Source: \`${c.event.source}\`
Tool: \`${c.event.tool ?? ""}\`

## Redacted input

\`\`\`json
${JSON.stringify(c.input, null, 2)}
\`\`\`

## Notes

The accompanying \`replacement.rule.yaml\` is a local replacement draft. Add registry fixtures that prove this false-positive input is allowed while the original malicious pattern still denies.
`;
}

function quoteYAML(value: string): string {
  return JSON.stringify(value);
}

function sanitizePathPart(value: string): string {
  return value.replace(/[^a-z0-9_.-]+/gi, "-").replace(/^-+|-+$/g, "") || "rule";
}
