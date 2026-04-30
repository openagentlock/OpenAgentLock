// `agentlock install` — detect every harness, multi-select the ones the
// user wants hardened, then drive the daemon's install pipeline end-to-
// end: mint an unattested session, preview the plan, confirm, apply.
//
// Design choices:
//   * Picker only lists harnesses with a real integration surface.
//     Anything that's purely sandboxed or has no public hook/MCP path
//     is filtered out — we don't show user-visible "not supported"
//     entries.
//   * In dev mode (AGENTLOCK_DEV_HOME set) every selectable harness is
//     enabled and the daemon writes a per-harness file under that dev
//     tree. Outside dev mode only Claude Code is enabled today; the
//     others are visible but disabled while their real integration
//     ships.
//   * Session is unattested (`signer: "none"`). Real attested sessions
//     require the signer tier ladder from docs/guide/signers.md, which the CLI
//     doesn't expose here yet.
//   * Dry-run by default: the plan is fetched first, printed, and the
//     user must pass `--yes` (or answer the prompt) before `apply`
//     fires. This matches our "everything an agent does is an explicit
//     touch" posture.
//   * `--daemon` overrides the control-plane URL. Defaults to
//     AGENTLOCK_CONTROL_PLANE_URL or http://127.0.0.1:7878.
//   * `--config-dir` overrides the Claude Code config dir specifically.
//     For multi-harness dev runs prefer AGENTLOCK_DEV_HOME=./dev which
//     re-roots every detector AND the daemon's apply paths.

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

import { detectAll } from "../detect/index.ts";
import type { HarnessId } from "../detect/types.ts";
import { multiselect } from "../tui/multiselect.tsx";
import { apiClient, type InstallFileOp } from "../util/api.ts";
import { home } from "../util/paths.ts";
import { mintAttestedSession, type AttestedTier } from "../util/session-mint.ts";

// Source-tree default: cli/agentlock is a bash wrapper that does
// `exec bun run cli/src/index.ts "$@"`, so harnesses can spawn
// `agentlock hook codex <event>` without needing a compiled binary.
// `process.execPath` alone points at `bun`, which crashes (exit 1) when
// invoked as `bun hook codex pre-tool-use` because `hook` isn't a script.
function defaultAgentlockBinary(): string {
  const wrapper = resolve(import.meta.dir, "..", "..", "agentlock");
  if (existsSync(wrapper)) return wrapper;
  return process.execPath;
}

type InstallTier = "unattested" | AttestedTier;

interface InstallFlags {
  yes: boolean;
  daemonUrl?: string;
  configDirOverride?: string;
  tier: InstallTier;
  totpCode?: string;
  totpPassphrase?: string;
}

function parseFlags(argv: string[]): InstallFlags {
  const flags: InstallFlags = { yes: false, tier: "unattested" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--yes" || a === "-y") flags.yes = true;
    else if (a === "--daemon" || a === "--daemon-url") flags.daemonUrl = argv[++i];
    else if (a === "--config-dir") flags.configDirOverride = argv[++i];
    else if (a === "--tier") {
      const v = argv[++i];
      if (v === "unattested" || v === "software" || v === "totp") {
        flags.tier = v;
      } else {
        throw new Error(`unknown --tier: ${v} (want unattested|software|totp)`);
      }
    } else if (a === "--code") flags.totpCode = argv[++i];
    else if (a === "--passphrase") flags.totpPassphrase = argv[++i];
  }
  // Resolve --config-dir to an absolute path against the CLI's CWD. The
  // daemon may be running with a different working directory (e.g. via
  // `cd control-plane && go run`) so a relative path would resolve
  // against the daemon's CWD, not the user's.
  if (flags.configDirOverride) {
    flags.configDirOverride = resolve(process.cwd(), flags.configDirOverride);
  }
  return flags;
}

async function promptYesNo(question: string): Promise<boolean> {
  process.stdout.write(question + " [y/N] ");
  return new Promise((resolve) => {
    const onData = (chunk: Buffer) => {
      const answer = chunk.toString("utf8").trim().toLowerCase();
      process.stdin.pause();
      process.stdin.off("data", onData);
      resolve(answer === "y" || answer === "yes");
    };
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

function summarizeOp(op: InstallFileOp): string {
  const tag = op.backup_path ? " (backup: " + op.backup_path + ")" : "";
  return `  ${op.op.padEnd(5)} ${op.path}${tag}\n    ${op.reason ?? ""}`;
}

export async function runInstall(argv: string[] = []): Promise<void> {
  const flags = parseFlags(argv);
  const api = apiClient(flags.daemonUrl);

  // Pre-resolve per-harness config dirs on the host side. The CLI knows
  // the user's real $HOME; the daemon (especially in Docker, where it
  // runs as uid 65532 with $HOME=/home/nonroot) does not. Sending these
  // explicitly avoids the host-vs-container path mismatch. When --config-
  // dir is set, mirror it for every harness so the legacy flag's "single
  // dir wins" behavior is preserved on both sides.
  const hostConfigDirs: Record<string, string> = flags.configDirOverride
    ? { "claude-code": flags.configDirOverride, codex: flags.configDirOverride }
    : {
        "claude-code": resolve(join(home(), ".claude")),
        codex: resolve(join(home(), ".codex")),
      };

  // 1. Detection ---------------------------------------------------------
  const devMode = !!process.env.AGENTLOCK_DEV_HOME;
  const results = await detectAll();
  const isMvpEnabled = (id: HarnessId): boolean =>
    id === "claude-code" || id === "codex";
  const options = results.map((r) => {
    const enabled = devMode || isMvpEnabled(r.id);
    let sub: string;
    if (r.agentlockInstalled) {
      // Make the existing wiring visible in the picker so a re-run can
      // tell at a glance which harnesses are already pointed at agentlock
      // (and at which daemon URL).
      sub = r.agentlockDaemonURL
        ? `wired → ${r.agentlockDaemonURL}`
        : "wired (daemon URL not recorded)";
    } else if (r.evidence.length > 0) {
      sub = r.evidence[0];
    } else {
      sub = "not detected (will create config on install)";
    }
    return {
      id: r.id,
      label: r.displayName,
      sub,
      // Pre-check rows that are already wired so a re-run defaults to
      // "keep current install" — pressing enter is a safe no-op (apply
      // is idempotent for claude and re-stamps the dev marker).
      checked: enabled && !!r.agentlockInstalled,
      disabled: !enabled,
      disabledReason: enabled ? undefined : "MVP: claude-code + codex only",
    };
  });

  // Snapshot the rows that the picker rendered as already-installed.
  // Anything in this set that is NOT in `chosen` after the picker closes
  // is a deselection — we'll uninstall those.
  const originallyInstalled = new Set<HarnessId>(
    results
      .filter((r) => r.agentlockInstalled && (devMode || isMvpEnabled(r.id)))
      .map((r) => r.id),
  );

  const chosen = await multiselect<HarnessId>({
    title: "Select agent harnesses to install agentlock into:",
    options,
  });

  if (chosen === null) {
    process.stdout.write("\naborted.\n");
    return;
  }

  const chosenSet = new Set<HarnessId>(chosen);
  const toUninstall: HarnessId[] = [];
  for (const id of originallyInstalled) {
    if (!chosenSet.has(id)) toUninstall.push(id);
  }
  if (chosen.length === 0 && toUninstall.length === 0) {
    process.stdout.write("\nnothing selected. exiting.\n");
    return;
  }

  // 2. Daemon connectivity ---------------------------------------------
  try {
    await api.health();
  } catch (err) {
    process.stderr.write(
      `\ncannot reach the OpenAgentLock daemon at ${api.baseUrl}.\n` +
        `  underlying error: ${(err as Error).message}\n\n` +
        `start the daemon and try again:\n` +
        `  curl -O https://raw.githubusercontent.com/openagentlock/OpenAgentLock/main/docker-compose.yml\n` +
        `  docker compose up -d\n` +
        `or override the URL with --daemon <url>.\n`,
    );
    process.exitCode = 2;
    return;
  }

  // 3. Session mint -----------------------------------------------------
  // Default is unattested (matches the "monitor mode default" posture
  // of the daemon). For prod use, callers pass --tier software|totp;
  // the daemon then accepts the install/uninstall flow under a real
  // signed session and ledger entries carry the strong signer banner.
  let sessionId: string;
  if (flags.tier === "unattested") {
    process.stdout.write(`\nminting unattested session on ${api.baseUrl}...\n`);
    try {
      const sess = await api.createUnattestedSession();
      sessionId = sess.id;
      process.stdout.write(`  session: ${sess.id} (${sess.banner ?? sess.signer})\n`);
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes("unattested_disabled")) {
        process.stderr.write(
          "\nunattested sessions are disabled on this daemon.\n" +
            "re-run with --tier totp (recommended) or --tier software, " +
            "or restart the daemon with -e AGENTLOCK_ALLOW_UNATTESTED=1.\n" +
            "see https://openagentlock.github.io/OpenAgentLock/guide/signers/\n",
        );
      } else {
        process.stderr.write(`\nsession mint failed: ${msg}\n`);
      }
      process.exitCode = 2;
      return;
    }
  } else {
    if (flags.tier === "totp" && (!flags.totpCode || !flags.totpPassphrase)) {
      process.stderr.write(
        "\n--tier totp requires --code <6-digit> and --passphrase <pp>.\n" +
          "enroll first with: agentlock signer enroll --tier totp --passphrase <pp>\n",
      );
      process.exitCode = 2;
      return;
    }
    process.stdout.write(
      `\nminting attested session (tier=${flags.tier}) on ${api.baseUrl}...\n`,
    );
    try {
      const sess = await mintAttestedSession({
        tier: flags.tier,
        url: flags.daemonUrl,
        code: flags.totpCode,
        passphrase: flags.totpPassphrase,
      });
      sessionId = sess.id;
      process.stdout.write(`  session: ${sess.id} (signer=${sess.signer})\n`);
    } catch (err) {
      const msg = (err as Error).message;
      process.stderr.write(`\nsession mint failed: ${msg}\n`);
      process.exitCode = 2;
      return;
    }
  }

  const daemonUrl = flags.daemonUrl ?? api.baseUrl;

  // 3.5. Capabilities probe -------------------------------------------
  // Read-only check against the daemon so we fail fast — before fetching
  // the plan, before showing y/N — when apply is disabled or when the
  // daemon's view of the host filesystem won't match the user's. Older
  // daemons (pre-0.1.10) don't expose this endpoint; treat 404/network
  // errors as "unknown" and fall through to the existing post-action
  // error handling.
  try {
    const caps = await api.installCapabilities();
    if (!caps.apply_enabled) {
      process.stderr.write(
        "\ninstall apply is disabled on this daemon.\n" +
          "restart the daemon with -e AGENTLOCK_ALLOW_APPLY=1 added.\n" +
          "see https://openagentlock.github.io/OpenAgentLock/guide/daemon-flags/\n",
      );
      process.exitCode = 2;
      return;
    }
    if (caps.container && !flags.configDirOverride) {
      process.stdout.write(
        "\nwarning: daemon is running in a container.\n" +
          "  install will reference your host paths (e.g. ~/.claude). For\n" +
          "  writes to actually land on the host, the daemon must have\n" +
          "  same-path bind mounts (e.g. -v $HOME/.claude:$HOME/.claude).\n" +
          "  see https://openagentlock.github.io/OpenAgentLock/guide/installation/\n",
      );
    }
  } catch {
    // Probe failed — older daemon or transient. Continue; downstream
    // calls will surface specific errors with the same hints.
  }

  // 3a. Per-harness uninstall for rows the user just deselected. Runs
  // before install/apply so the ledger entries land in a sensible
  // chronological order (uninstall, then install).
  if (toUninstall.length > 0) {
    process.stdout.write(
      `\nuninstalling deselected harnesses: ${toUninstall.join(", ")}\n`,
    );
    try {
      const u = await api.installUninstallHarnesses({
        session_id: sessionId,
        harnesses: toUninstall,
        config_dir_override: flags.configDirOverride,
        harness_config_dirs: hostConfigDirs,
      });
      for (const op of u.operations) {
        const note = op.error ? `  ERROR: ${op.error}` : "";
        process.stdout.write(
          `  ${op.op.padEnd(6)} ${op.path}  (removed=${op.entries_removed})${note}\n`,
        );
      }
      if (u.failures > 0) {
        process.stderr.write(
          `\n${u.failures} uninstall op(s) failed; see above. Continuing with install.\n`,
        );
      }
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes("apply_disabled")) {
        process.stderr.write(
          "\nuninstall is disabled on this daemon.\n" +
            "restart the daemon with -e AGENTLOCK_ALLOW_APPLY=1 added.\n" +
            "see https://openagentlock.github.io/OpenAgentLock/guide/daemon-flags/\n",
        );
        process.exitCode = 2;
        return;
      }
      process.stderr.write(`\nuninstall failed: ${msg}\n`);
      // Continue: a failed uninstall shouldn't block re-installing the
      // ones the user kept selected.
    }
  }

  if (chosen.length === 0) {
    process.stdout.write("\nno harnesses selected for install. done.\n");
    return;
  }

  const planReq = {
    session_id: sessionId,
    harnesses: chosen,
    daemon_url: daemonUrl,
    config_dir_override: flags.configDirOverride,
    // Pass an absolute path so Codex's command-hook spawn doesn't depend
    // on PATH at hook-fire time. Source-tree dev runs use the
    // `cli/agentlock` wrapper; AGENTLOCK_BINARY lets release builds
    // override (e.g. point at the compiled single-file binary).
    agentlock_binary: process.env.AGENTLOCK_BINARY ?? defaultAgentlockBinary(),
    harness_config_dirs: hostConfigDirs,
  };

  // 4. Plan dry-run ------------------------------------------------------
  process.stdout.write(`\nfetching install plan for: ${chosen.join(", ")}\n`);
  let plan: Awaited<ReturnType<typeof api.installPlan>>;
  try {
    plan = await api.installPlan(planReq);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`plan failed: ${msg}\n`);
    if (msg.includes("unknown_session")) {
      process.stderr.write(
        "hint: the daemon didn't recognise the session. Retry; if it persists restart the daemon.\n",
      );
    } else if (msg.includes("ECONNREFUSED") || msg.includes("fetch failed")) {
      process.stderr.write(
        "hint: daemon not reachable on 127.0.0.1:7878. Start it with:\n" +
          "  docker run -d --name agentlock -p 127.0.0.1:7878:7878 ghcr.io/openagentlock/agentlockd:latest\n" +
          "Already running? Check `docker logs agentlock` (or `just cp-serve` for a source checkout).\n",
      );
    }
    process.exitCode = 2;
    return;
  }
  if (plan.skipped.length > 0) {
    process.stdout.write(`  skipped (unsupported): ${plan.skipped.join(", ")}\n`);
  }
  if (plan.warnings && plan.warnings.length > 0) {
    process.stdout.write("\nwarnings:\n");
    for (const w of plan.warnings) {
      process.stdout.write(`  ! ${w}\n`);
    }
  }
  if (plan.operations.length === 0) {
    process.stdout.write("  no operations to apply. exiting.\n");
    return;
  }
  process.stdout.write(
    `\nplan (${plan.operations.length} file op${plan.operations.length === 1 ? "" : "s"}):\n`,
  );
  for (const op of plan.operations) {
    process.stdout.write(summarizeOp(op) + "\n");
  }

  // 5. Confirm -----------------------------------------------------------
  if (!flags.yes) {
    const ok = await promptYesNo("\napply plan?");
    if (!ok) {
      process.stdout.write("aborted. no changes.\n");
      return;
    }
  }

  // 6. Apply -------------------------------------------------------------
  process.stdout.write("\napplying...\n");
  try {
    const result = await api.installApply(planReq);
    process.stdout.write(
      `  applied=${result.applied}  manifest=${result.manifest_path}\n`,
    );
    for (const op of result.operations) {
      process.stdout.write(summarizeOp(op) + "\n");
    }
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes("apply_disabled")) {
      process.stderr.write(
        "\ninstall apply is disabled on this daemon.\n" +
          "restart the daemon with -e AGENTLOCK_ALLOW_APPLY=1 added.\n" +
          "see https://openagentlock.github.io/OpenAgentLock/guide/daemon-flags/\n",
      );
    } else if (msg.includes("unsafe_target")) {
      process.stderr.write(
        "\ndaemon refused to write to a path under real ~/.claude or ~/.codex.\n" +
          "use --config-dir ./dev/.claude (or ./dev/.codex) for dev runs, or set\n" +
          "AGENTLOCK_ALLOW_APPLY_REAL_HOME=1 on the daemon for real installs.\n",
      );
    } else if (msg.includes("codex_hooks_disabled")) {
      process.stderr.write(
        "\ncodex install refused: codex_hooks must be enabled first.\n" +
          "add `codex_hooks = true` to your ~/.codex/config.toml and retry.\n",
      );
    } else {
      process.stderr.write(`\napply failed: ${msg}\n`);
    }
    process.exitCode = 2;
    return;
  }

  process.stdout.write(
    "\ndone. restart your agent harness so it re-reads settings.json.\n",
  );
}
