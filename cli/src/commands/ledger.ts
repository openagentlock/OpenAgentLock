import { apiClient } from "../util/api";

export interface LedgerRootOptions {
  url?: string;
  json: boolean;
}

export async function runLedgerRoot(opts: LedgerRootOptions): Promise<void> {
  const client = apiClient(opts.url);
  const r = await client.ledgerRoot();
  if (opts.json) {
    process.stdout.write(JSON.stringify(r, null, 2) + "\n");
    return;
  }
  process.stdout.write(
    `root:        ${r.root}\n` +
      `count:       ${r.count}\n` +
      `last_seq:    ${r.seq}\n` +
      `computed_at: ${r.computed_at}\n`,
  );
}

export interface LedgerVerifyOptions {
  url?: string;
  json: boolean;
}

export async function runLedgerVerify(opts: LedgerVerifyOptions): Promise<void> {
  const client = apiClient(opts.url);
  const r = await client.ledgerVerify();
  if (opts.json) {
    process.stdout.write(JSON.stringify(r, null, 2) + "\n");
  } else if (r.ok) {
    process.stdout.write(`ok    root=${r.root}  count=${r.count}\n`);
  } else {
    process.stdout.write(
      `FAIL  count=${r.count}  first_bad_at=${r.first_bad_at}\n` +
        `      reason=${r.reason}\n`,
    );
  }
  if (!r.ok) process.exit(4);
}
