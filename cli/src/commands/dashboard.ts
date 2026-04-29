// `agentlock dashboard` — an OpenTUI viewer over the daemon's JSON +
// SSE endpoints. Read-mostly today: event stream, sessions, loaded
// gates, daemon mode (with a one-key flip). Edit flows still live on
// the web dashboard.

import { apiClient } from "../util/api.ts";
import { readPassword, readPrompt } from "../util/prompt.ts";
import { runDashboardTUI } from "../tui/dashboard.tsx";

export interface DashboardOpts {
  daemon?: string;
  token?: string;
}

export async function runDashboard(opts: DashboardOpts = {}): Promise<void> {
  const api = apiClient(opts.daemon, opts.token);

  // Eagerly probe /v1/health once so we fail fast with a clear message
  // instead of dropping the user into a TUI that can't reach the daemon.
  try {
    await api.health();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `daemon unreachable at ${api.baseUrl}: ${msg}\n` +
        "hint: run `just cp-serve` in another terminal first.\n",
    );
    process.exitCode = 2;
    return;
  }

  // Probe auth mode. When the daemon requires a password and we don't
  // already have a token, prompt for one up front. Keeps the TUI from
  // booting into a wall of 401s.
  try {
    const mode = await api.authMode();
    if (mode.mode === "password" && !api.token) {
      if (!mode.users_configured) {
        process.stderr.write(
          "daemon has AGENTLOCK_AUTH=password but no users configured.\n" +
            "run `agentlock login --bootstrap` first.\n",
        );
        process.exitCode = 2;
        return;
      }
      process.stdout.write(
        "control-plane requires password auth. enter credentials:\n",
      );
      const username = await readPrompt("username: ");
      const password = await readPassword("password: ");
      try {
        await api.authLogin(username, password);
      } catch (err) {
        process.stderr.write(
          `login failed: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 2;
        return;
      }
    }
  } catch {
    // /v1/auth/mode shouldn't fail unless the daemon is wedged; health
    // already passed, so continue and let per-tab errors surface.
  }

  await runDashboardTUI(api);
}
