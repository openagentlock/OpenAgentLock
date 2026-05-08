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

import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { detectAll } from "../detect/index.ts";
import type { HarnessId } from "../detect/types.ts";
import { multiselect } from "../tui/multiselect.tsx";
import { apiClient, type InstallFileOp } from "../util/api.ts";
import {
  checkSafeTarget,
  executeFileOps,
  executeUninstallOps,
  listExtensionBundleManifests,
  listJsonFiles,
  readExistingFiles,
} from "../util/install-fs.ts";
import { claudeDesktopConfigPath } from "../detect/claude-desktop.ts";
import { binDir, home, isWin } from "../util/paths.ts";
import { mintAttestedSession, type AttestedTier } from "../util/session-mint.ts";

// Stable wrapper path: <agentlockHome>/bin/agentlock. Lives in our state dir,
// not in the package manager's volatile node_modules tree, so package
// upgrades / reinstalls don't strand the wired hook command at a path the
// shell can't spawn (which renders as red "PreToolUse hook error" banners
// in Claude Code, and similar in Cursor / Codex). Re-running `agentlock
// install` rewrites the wrapper, picking up any new index.ts location.
//
// The wrapper itself is bash-only — Windows wiring lands separately.
export function installAndResolveAgentlockBinary(): string {
  if (isWin()) {
    throw new Error(
      "agentlock install: Windows wrapper not yet supported. Use macOS/Linux for now.",
    );
  }
  const indexPath = resolve(import.meta.dir, "..", "index.ts");
  const dir = binDir();
  const wrapper = join(dir, "agentlock");
  const body = `#!/usr/bin/env bash\nexec bun run "${indexPath}" "$@"\n`;
  mkdirSync(dir, { recursive: true });
  writeFileSync(wrapper, body, { flag: "w" });
  chmodSync(wrapper, 0o755);
  return wrapper;
}

// Tiny health-check script wired into Claude Code's `statusLine` config.
// Output renders as a UI element under the chat — never injected into the
// model's input stream — so the user sees live "is the daemon up?" without
// a prompt-injection vector. Curl with a 200ms timeout keeps the status
// line snappy; a hung daemon fails to "offline" instead of stalling the UI.
export function installStatusLineScript(): string {
  if (isWin()) {
    throw new Error(
      "agentlock install: Windows status-line not yet supported. Use macOS/Linux for now.",
    );
  }
  const dir = binDir();
  const script = join(dir, "agentlock-status");
  const body = `#!/usr/bin/env bash
url="\${AGENTLOCK_DAEMON_URL:-http://127.0.0.1:7878}"
if curl --max-time 1 -fs "$url/v1/health" >/dev/null 2>&1; then
  printf 'OpenAgentLock \\xe2\\x9c\\x93'
else
  printf 'OpenAgentLock \\xe2\\x9a\\xa0 daemon offline'
fi
`;
  mkdirSync(dir, { recursive: true });
  writeFileSync(script, body, { flag: "w" });
  chmodSync(script, 0o755);
  return script;
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
  // Claude Desktop's config sits under platform-specific Application
  // Support / APPDATA dirs, not under a "~/.claude" sibling. Resolve via
  // the detector helper so dev mode (AGENTLOCK_DEV_HOME) and real-host
  // mode share one source of truth for the path.
  const claudeDesktopDir = resolve(join(claudeDesktopConfigPath(), ".."));
  const hostConfigDirs: Record<string, string> = flags.configDirOverride
    ? {
        "claude-code": flags.configDirOverride,
        "claude-desktop": flags.configDirOverride,
        codex: flags.configDirOverride,
        cursor: flags.configDirOverride,
        gemini: flags.configDirOverride,
      }
    : {
        "claude-code": resolve(join(home(), ".claude")),
        "claude-desktop": claudeDesktopDir,
        codex: resolve(join(home(), ".codex")),
        cursor: resolve(join(home(), ".cursor")),
        gemini: resolve(join(home(), ".gemini")),
      };

  // 1. Detection ---------------------------------------------------------
  const devMode = !!process.env.AGENTLOCK_DEV_HOME;
  const results = await detectAll();
  const isMvpEnabled = (id: HarnessId): boolean =>
    id === "claude-code" ||
    id === "claude-desktop" ||
    id === "codex" ||
    id === "cursor" ||
    id === "gemini";
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
      disabledReason: enabled ? undefined : "MVP: claude-code + codex + cursor only",
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
  // The daemon no longer writes host files (the CLI does), so there's
  // no apply / real-home gate to check. We still call the endpoint so
  // unattested-disabled daemons surface early — but the check above
  // (createUnattestedSession) already covers that case for tier=unattested.
  // Older daemons (pre-0.1.10) don't expose the endpoint; ignore.
  try {
    await api.installCapabilities();
  } catch {
    // Probe failed — older daemon or transient. Continue; downstream
    // calls will surface specific errors.
  }

  // 3a. Per-harness uninstall for rows the user just deselected. Runs
  // before install/apply so the ledger entries land in a sensible
  // chronological order (uninstall, then install).
  if (toUninstall.length > 0) {
    process.stdout.write(
      `\nuninstalling deselected harnesses: ${toUninstall.join(", ")}\n`,
    );
    // Pass the current contents of every per-harness file so the daemon
    // can compute the post-strip bytes without reading host paths.
    const uninstallPaths: string[] = [];
    for (const id of toUninstall) {
      const dir = hostConfigDirs[id];
      if (!dir) continue;
      if (id === "claude-code") {
        uninstallPaths.push(resolve(join(dir, "settings.json")));
      } else if (id === "claude-desktop") {
        uninstallPaths.push(resolve(join(dir, "claude_desktop_config.json")));
        // Bundle manifests live one dir over and are the actual launch
        // source for Desktop Extensions — the daemon needs each to
        // unwind the wrap on uninstall.
        const bundlesDir = resolve(join(dir, "Claude Extensions"));
        uninstallPaths.push(...(await listExtensionBundleManifests(bundlesDir)));
      } else if (id === "codex" || id === "cursor") {
        uninstallPaths.push(resolve(join(dir, "hooks.json")));
      } else if (id === "gemini") {
        // Gemini stuffs hook entries into the same settings.json as
        // every other CLI setting — no separate hooks.json file.
        uninstallPaths.push(resolve(join(dir, "settings.json")));
      }
    }
    const uninstallExisting = await readExistingFiles(uninstallPaths);
    try {
      const u = await api.installUninstallHarnesses({
        session_id: sessionId,
        harnesses: toUninstall,
        config_dir_override: flags.configDirOverride,
        harness_config_dirs: hostConfigDirs,
        existing_files: uninstallExisting,
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
      } else {
        // Execute the strip / remove ops on the host now that the daemon
        // has signed the diff into the ledger.
        await executeUninstallOps(u.operations);
      }
    } catch (err) {
      const msg = (err as Error).message;
      process.stderr.write(`\nuninstall failed: ${msg}\n`);
      // Continue: a failed uninstall shouldn't block re-installing the
      // ones the user kept selected.
    }
  }

  if (chosen.length === 0) {
    process.stdout.write("\nno harnesses selected for install. done.\n");
    return;
  }

  // Read every host file the daemon needs to merge against, so the plan
  // ops carry the final byte-for-byte content the CLI will write. Missing
  // files are silently skipped (readExistingFiles drops ENOENT).
  const claudeSettings = resolve(
    join(hostConfigDirs["claude-code"], "settings.json"),
  );
  const claudeDesktopConfig = resolve(
    join(hostConfigDirs["claude-desktop"], "claude_desktop_config.json"),
  );
  const codexHooks = resolve(join(hostConfigDirs["codex"], "hooks.json"));
  const codexConfig = resolve(join(hostConfigDirs["codex"], "config.toml"));
  const cursorHooks = resolve(join(hostConfigDirs["cursor"], "hooks.json"));
  const geminiSettings = resolve(
    join(hostConfigDirs["gemini"], "settings.json"),
  );
  // Per-extension bundle manifests are THE launch source for Desktop
  // Extensions installed via Settings → Extensions UI — claudeDesktopPlan
  // wraps each one in place using the schema-blessed _meta.agentlock
  // slot (MCPB v0.3+). The Claude Extensions Settings sidecar JSONs
  // tell us which extensions are isEnabled so disabled ones get
  // unwound rather than re-wrapped.
  const claudeDesktopBundlesDir = resolve(
    join(hostConfigDirs["claude-desktop"], "Claude Extensions"),
  );
  const claudeDesktopExtSettingsDir = resolve(
    join(hostConfigDirs["claude-desktop"], "Claude Extensions Settings"),
  );
  const bundleManifests = await listExtensionBundleManifests(
    claudeDesktopBundlesDir,
  );
  const extSettingsFiles = await listJsonFiles(claudeDesktopExtSettingsDir);
  const existingFiles = await readExistingFiles([
    claudeSettings,
    claudeDesktopConfig,
    codexHooks,
    codexConfig,
    cursorHooks,
    geminiSettings,
    ...bundleManifests,
    ...extSettingsFiles,
  ]);

  // Write the status-line script alongside the binary wrapper. Daemon
  // wires this path into ~/.claude/settings.json `statusLine` so users
  // see live OAL health without any chat injection.
  const statusLineScript = installStatusLineScript();

  const planReq = {
    session_id: sessionId,
    harnesses: chosen,
    daemon_url: daemonUrl,
    config_dir_override: flags.configDirOverride,
    // Pass an absolute path so Codex's command-hook spawn doesn't depend
    // on PATH at hook-fire time. The wrapper lives under agentlockHome()
    // so it survives package-manager upgrades; AGENTLOCK_BINARY lets
    // release builds override (e.g. point at a compiled single-file binary).
    agentlock_binary: process.env.AGENTLOCK_BINARY ?? installAndResolveAgentlockBinary(),
    status_line_script: statusLineScript,
    harness_config_dirs: hostConfigDirs,
    existing_files: existingFiles,
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

  // 5.5. Safety check + execute on the host ---------------------------
  // The plan was returned by the daemon but it never touched disk. We
  // refuse paths that don't resolve under one of the real harness home
  // subtrees unless the caller explicitly opted into a dev sandbox via
  // --config-dir or AGENTLOCK_DEV_HOME.
  const bypass =
    !!flags.configDirOverride || !!process.env.AGENTLOCK_DEV_HOME;
  try {
    for (const op of plan.operations) {
      checkSafeTarget(op.path, { bypass });
    }
  } catch (err) {
    process.stderr.write(`\n${(err as Error).message}\n`);
    process.stderr.write(
      "use --config-dir ./dev/.claude (or ./dev/.codex, ./dev/.cursor, ./dev/.gemini) for dev runs.\n",
    );
    process.exitCode = 2;
    return;
  }
  try {
    await executeFileOps(plan.operations);
  } catch (err) {
    process.stderr.write(`\nfile write failed: ${(err as Error).message}\n`);
    process.exitCode = 2;
    return;
  }

  // 6. Apply -------------------------------------------------------------
  // Files are already on disk; this call records the manifest + signs
  // the install into the ledger.
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
    process.stderr.write(`\napply failed: ${msg}\n`);
    process.exitCode = 2;
    return;
  }

  process.stdout.write(
    "\ndone. restart your agent harness so it re-reads settings.json.\n",
  );
}
