// Simulate an agent-harness tool-call hook without actually wiring a
// harness. Exists so we can end-to-end the full pipeline
//   fake-hook → control-plane /v1/gates/check → policy → ledger
// without depending on Claude Code / Cursor / Codex being installed.

import { apiClient, type GateCheckRequest, type GateCheckResponse } from "../util/api";

export interface FakeHookOptions {
  session: string;
  source: string;
  tool: string;
  command?: string;
  filePath?: string;
  url?: string;
  json: boolean;
  inputJson?: string;
}

export async function runFakeHook(opts: FakeHookOptions): Promise<void> {
  const input: Record<string, unknown> = {};
  if (opts.inputJson) {
    try {
      Object.assign(input, JSON.parse(opts.inputJson));
    } catch (e) {
      process.stderr.write(`--input: invalid JSON: ${(e as Error).message}\n`);
      process.exit(2);
    }
  }
  if (opts.command !== undefined) input.command = opts.command;
  if (opts.filePath !== undefined) input.file_path = opts.filePath;

  const req: GateCheckRequest = {
    session_id: opts.session,
    source: opts.source,
    tool: opts.tool,
    input,
  };
  const client = apiClient(opts.url);
  let res: GateCheckResponse;
  try {
    res = await client.checkGate(req);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`fake-hook: gate check failed (${opts.url ?? "default url"}): ${msg}\n`);
    process.exit(1);
  }
  if (!res || !res.verdict) {
    process.stderr.write(`fake-hook: malformed gate response\n`);
    process.exit(1);
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  } else {
    const tag = res.monitor ? "monitor-match" : res.verdict;
    process.stdout.write(
      `verdict:   ${tag}\n` +
        `rule:      ${res.rule_id}\n` +
        `reason:    ${res.reason}\n` +
        `ledger_seq: ${res.ledger_seq}\n`,
    );
  }
  if (res.verdict === "deny") process.exit(3);
}
