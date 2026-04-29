// `agentlock login` — interactive password login when the control-plane
// has AGENTLOCK_AUTH=password on. Prints the bearer token (and an
// export snippet) so downstream CLI invocations can pass --token or set
// AGENTLOCK_TOKEN.
//
// Supports --bootstrap to create the first user when users.json is empty.

import { apiClient } from "../util/api.ts";
import { readPrompt, readPassword } from "../util/prompt.ts";

export interface LoginOpts {
  daemon?: string;
  bootstrap?: boolean;
  username?: string;
  // When password is set, the flow is fully non-interactive. Intended
  // for CI scripts and e2e tests where a TTY isn't available. Avoid in
  // shell history — prefer AGENTLOCK_PASSWORD via the environment.
  password?: string;
  json?: boolean;
}

export async function runLogin(opts: LoginOpts = {}): Promise<void> {
  const api = apiClient(opts.daemon);

  // Probe mode first so we can give a useful message.
  let mode;
  try {
    mode = await api.authMode();
  } catch (err) {
    process.stderr.write(
      `daemon unreachable at ${api.baseUrl}: ${err instanceof Error ? err.message : err}\n` +
        "hint: run `just cp-serve` in another terminal first.\n",
    );
    process.exitCode = 2;
    return;
  }

  if (mode.mode === "none") {
    process.stderr.write(
      "daemon auth is disabled (AGENTLOCK_AUTH=none). No login required.\n",
    );
    process.exitCode = 0;
    return;
  }
  if (mode.mode !== "password") {
    process.stderr.write(
      `daemon auth mode is ${mode.mode}; only password is CLI-wired today. See docs/guide/auth.md.\n`,
    );
    process.exitCode = 2;
    return;
  }

  // Non-interactive path (used by CI / e2e): --password flag or
  // $AGENTLOCK_PASSWORD. Must pair with --username.
  const envPw = process.env.AGENTLOCK_PASSWORD;
  const scriptedPw = opts.password ?? envPw;

  if (opts.bootstrap) {
    if (mode.users_configured) {
      process.stderr.write(
        "at least one user is already configured; bootstrap would be refused by the daemon.\n" +
          "use `agentlock login` (no --bootstrap) to get a token for the existing user.\n",
      );
      process.exitCode = 2;
      return;
    }
    const username =
      opts.username ?? (scriptedPw ? "admin" : await readPrompt("new admin username: "));
    const password =
      scriptedPw ?? (await readPassword("new admin password (>= 10 chars): "));
    try {
      await api.authBootstrap(username, password);
      process.stdout.write(`created user "${username}". logging in...\n`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`bootstrap failed: ${msg}\n`);
      process.exitCode = 2;
      return;
    }
    await doLogin(api, username, password, opts.json);
    return;
  }

  const username =
    opts.username ?? (scriptedPw ? "admin" : await readPrompt("username: "));
  const password = scriptedPw ?? (await readPassword("password: "));
  await doLogin(api, username, password, opts.json);
}

async function doLogin(
  api: ReturnType<typeof apiClient>,
  username: string,
  password: string,
  json: boolean | undefined,
): Promise<void> {
  let res;
  try {
    res = await api.authLogin(username, password);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`login failed: ${msg}\n`);
    process.exitCode = 2;
    return;
  }
  if (json) {
    process.stdout.write(JSON.stringify(res) + "\n");
    return;
  }
  const expiresAt = new Date(res.expires_at * 1000).toISOString();
  process.stdout.write(
    `logged in as ${res.username}. token expires ${expiresAt}.\n\n` +
      "export AGENTLOCK_TOKEN=" +
      res.token +
      "\n\n" +
      "or pass --token to subsequent commands.\n",
  );
}
