// `agentlock status` — probe the control-plane. MVP prints health +
// the daemon URL. Later this grows session state, signer kind, pending
// approvals count, current Merkle root.

import { apiClient } from "../util/api.ts";

export interface StatusOptions {
  url?: string;
  json: boolean;
}

export async function runStatus(opts: StatusOptions): Promise<void> {
  const client = apiClient(opts.url);
  try {
    const health = await client.health();
    if (opts.json) {
      process.stdout.write(
        JSON.stringify(
          { reachable: true, base_url: client.baseUrl, health },
          null,
          2,
        ) + "\n",
      );
      return;
    }
    process.stdout.write(`control-plane: ${client.baseUrl}\n`);
    process.stdout.write(`  status: ${health.status}\n`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (opts.json) {
      process.stdout.write(
        JSON.stringify(
          { reachable: false, base_url: client.baseUrl, error: msg },
          null,
          2,
        ) + "\n",
      );
    } else {
      process.stderr.write(
        `control-plane: ${client.baseUrl}\n  unreachable: ${msg}\n`,
      );
    }
    process.exitCode = 1;
  }
}
