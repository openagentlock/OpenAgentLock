#!/usr/bin/env bun
// agentlock — TUI for hardening AI coding agent usage.
// Entry point. Subcommands:
//   detect   — list detected agent harnesses (no TUI, plain stdout)
//   install  — interactive selector; stops after selection
//
// All side-effecting commands are intentionally limited to stdout for now.
// See docs/api/openapi.yaml for the control-plane API that will execute
// install once it's signed off.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Command } from "commander";
import { runDashboard } from "./commands/dashboard.ts";
import { runDetect } from "./commands/detect.ts";
import { runInstall } from "./commands/install.ts";
import { runLogin } from "./commands/login.ts";
import { runStatus } from "./commands/status.ts";
import { runSessionCreate, runSessionEnd, runSessionRotate } from "./commands/session.ts";
import { runFakeHook } from "./commands/fake-hook.ts";
import { runHookClaudeCode } from "./commands/hook-claude-code.ts";
import { runHookCodex } from "./commands/hook-codex.ts";
import { runHookCursor } from "./commands/hook-cursor.ts";
import { runHookGemini } from "./commands/hook-gemini.ts";
import { runLedgerRoot, runLedgerVerify } from "./commands/ledger.ts";
import { runMcpProxy } from "./commands/mcp-proxy.ts";
import { runMcpServer } from "./commands/mcp-server.ts";
import { runSignerEnroll } from "./commands/signer-enroll.ts";
import {
  runRulesAdd,
  runRulesInstall,
  runRulesRemove,
  runRulesSearch,
  runRulesSources,
  runRulesSync,
  runRulesUninstall,
} from "./commands/rules.ts";

// Read version from the published package.json so `agentlock --version`
// always matches the installed npm version, no hand-bumping required.
const PKG_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
const PKG_VERSION = (JSON.parse(readFileSync(PKG_PATH, "utf8")) as { version: string }).version;

const program = new Command();

program
  .name("agentlock")
  .description("Local-first hardening for AI coding agents.")
  .version(PKG_VERSION);

program
  .command("detect")
  .description("List detected agent harnesses on this machine.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { json: boolean }) => {
    await runDetect({ json: opts.json });
  });

program
  .command("install")
  .description(
    "Interactive selector. Detects harnesses, mints a session (default: unattested), fetches the install plan, confirms with you, then POSTs /v1/install/apply.",
  )
  .option("-y, --yes", "Skip the apply confirmation prompt.")
  .option(
    "--daemon <url>",
    "Control-plane base URL (env: AGENTLOCK_CONTROL_PLANE_URL). Default: http://127.0.0.1:7878.",
  )
  .option(
    "--config-dir <path>",
    "Override the per-harness config directory (e.g. ./dev/.claude for dev runs). Default: the harness's real user home path.",
  )
  .option(
    "--tier <tier>",
    "Session signer tier: unattested (default; daemon must allow it), software (dev/CI), or totp (prod, requires prior `agentlock signer enroll --tier totp`).",
  )
  .option("--code <code>", "TOTP 6-digit code (required when --tier totp).")
  .option(
    "--passphrase <pp>",
    "Passphrase used at enrollment (required when --tier totp).",
  )
  .action(
    async (opts: {
      yes?: boolean;
      daemon?: string;
      configDir?: string;
      tier?: string;
      code?: string;
      passphrase?: string;
    }) => {
      const argv: string[] = [];
      if (opts.yes) argv.push("--yes");
      if (opts.daemon) argv.push("--daemon", opts.daemon);
      if (opts.configDir) argv.push("--config-dir", opts.configDir);
      if (opts.tier) argv.push("--tier", opts.tier);
      if (opts.code) argv.push("--code", opts.code);
      if (opts.passphrase) argv.push("--passphrase", opts.passphrase);
      await runInstall(argv);
    },
  );

program
  .command("dashboard")
  .description(
    "Open the OpenTUI dashboard. Live ledger tail, sessions, loaded gates, and a one-key firewall/monitor flip.",
  )
  .option(
    "--daemon <url>",
    "Control-plane base URL (env: AGENTLOCK_CONTROL_PLANE_URL). Default: http://127.0.0.1:7878.",
  )
  .option(
    "--token <token>",
    "Bearer token when the daemon has AGENTLOCK_AUTH=password enabled (env: AGENTLOCK_TOKEN).",
  )
  .action(async (opts: { daemon?: string; token?: string }) => {
    await runDashboard({ daemon: opts.daemon, token: opts.token });
  });

program
  .command("login")
  .description(
    "Interactive password login against the control-plane when AGENTLOCK_AUTH=password. Prints a bearer token.",
  )
  .option("--daemon <url>", "Control-plane base URL (env: AGENTLOCK_CONTROL_PLANE_URL).")
  .option("--bootstrap", "Create the first admin user (refused once any user exists).")
  .option("--username <user>", "Non-interactive username.")
  .option(
    "--password <password>",
    "Non-interactive password (env: AGENTLOCK_PASSWORD). Avoid in shell history.",
  )
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      daemon?: string;
      bootstrap?: boolean;
      username?: string;
      password?: string;
      json: boolean;
    }) => {
      await runLogin(opts);
    },
  );

program
  .command("status")
  .description("Probe the control-plane (OpenAgentLock daemon) at 127.0.0.1:7878.")
  .option(
    "--url <url>",
    "Override the control-plane base URL (env: AGENTLOCK_CONTROL_PLANE_URL).",
  )
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { url?: string; json: boolean }) => {
    await runStatus({ url: opts.url, json: opts.json });
  });

const session = program
  .command("session")
  .description("Session management.");

session
  .command("create")
  .description("Open a new session. Signs an attestation with the host signer and POSTs it to the control-plane.")
  .option("--tier <tier>", "Signer tier (software | totp).", "software")
  .option("--url <url>", "Control-plane base URL.")
  .option("--policy-hash <hash>", "Policy hash to bind into the attestation.")
  .option("--user-id <id>", "User identity used for group-policy overlays.")
  .option("--group <name...>", "Group memberships used for group-policy overlays.")
  .option("--code <6-digit>", "TOTP code (required for --tier totp).")
  .option("--passphrase <pp>", "TOTP passphrase (required for --tier totp).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      tier: string;
      url?: string;
      policyHash?: string;
      userId?: string;
      group?: string[];
      code?: string;
      passphrase?: string;
      json: boolean;
    }) => {
      if (opts.tier !== "software" && opts.tier !== "totp" && opts.tier !== "os-keychain") {
        process.stderr.write(
          `--tier ${opts.tier} is not supported.\n` +
            `available tiers: software (dev/CI), totp (recommended for prod), os-keychain (macOS).\n` +
            `Hardware-key (YubiKey) tiers are on the roadmap; see\n` +
            `https://openagentlock.github.io/OpenAgentLock/guide/signers/\n`,
        );
        process.exit(2);
      }
      if (opts.tier === "totp" && (!opts.code || !opts.passphrase)) {
        process.stderr.write(
          `--tier totp requires --code <6-digit> and --passphrase <pp>.\n` +
            `enroll first with: agentlock signer enroll --tier totp --passphrase <pp>\n` +
            `then read the current 6-digit code from your authenticator app.\n`,
        );
        process.exit(2);
      }
      await runSessionCreate({
        tier: opts.tier as "software" | "totp" | "os-keychain",
        url: opts.url,
        json: opts.json,
        policyHash: opts.policyHash,
        userId: opts.userId,
        groups: opts.group,
        code: opts.code,
        passphrase: opts.passphrase,
      });
    },
  );

session
  .command("end")
  .description("End a session — any subsequent gate check returns 410 Gone.")
  .requiredOption("--id <id>", "Session ID.")
  .option("--url <url>", "Control-plane base URL.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { id: string; url?: string; json: boolean }) => {
    await runSessionEnd(opts);
  });

session
  .command("rotate")
  .description("Rotate a session — sign a fresh attestation and replace the in-memory session key.")
  .requiredOption("--id <id>", "Session ID.")
  .option("--tier <tier>", "Signer tier (software | totp).", "software")
  .option("--url <url>", "Control-plane base URL.")
  .option("--policy-hash <hash>", "Policy hash to bind into the rotated attestation.")
  .option("--user-id <id>", "User identity used for group-policy overlays.")
  .option("--group <name...>", "Group memberships used for group-policy overlays.")
  .option("--code <6-digit>", "TOTP code (required for --tier totp).")
  .option("--passphrase <pp>", "TOTP passphrase (required for --tier totp).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      id: string;
      tier: string;
      url?: string;
      policyHash?: string;
      userId?: string;
      group?: string[];
      code?: string;
      passphrase?: string;
      json: boolean;
    }) => {
      if (opts.tier !== "software" && opts.tier !== "totp" && opts.tier !== "os-keychain") {
        process.stderr.write(
          `--tier ${opts.tier} is not supported.\n` +
            `available tiers: software (dev/CI), totp (recommended for prod), os-keychain (macOS).\n`,
        );
        process.exit(2);
      }
      if (opts.tier === "totp" && (!opts.code || !opts.passphrase)) {
        process.stderr.write(
          `--tier totp requires --code <6-digit> and --passphrase <pp>.\n`,
        );
        process.exit(2);
      }
      await runSessionRotate({
        id: opts.id,
        tier: opts.tier as "software" | "totp" | "os-keychain",
        url: opts.url,
        json: opts.json,
        policyHash: opts.policyHash,
        userId: opts.userId,
        groups: opts.group,
        code: opts.code,
        passphrase: opts.passphrase,
      });
    },
  );

const signer = program
  .command("signer")
  .description("Signer enrollment + status.");

signer
  .command("enroll")
  .description("Enroll a long-lived signer. Supported tiers: totp, os-keychain (macOS). Hardware-key (YubiKey) is on the roadmap.")
  .requiredOption("--tier <tier>", "Signer tier (totp | os-keychain).")
  .option("--passphrase <pp>", "Passphrase used to seal the signing key (required for totp).")
  .option("--label <label>", "otpauth label (default: agentlock).")
  .option("--issuer <issuer>", "otpauth issuer (default: OpenAgentLock).")
  .option(
    "--ttl <duration>",
    "Reject the os-keychain signer after this duration. Examples: 30m, 4h, 7d. Omit for no expiry.",
  )
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      tier: string;
      passphrase?: string;
      label?: string;
      issuer?: string;
      ttl?: string;
      json: boolean;
    }) => {
      if (opts.tier !== "totp" && opts.tier !== "os-keychain") {
        process.stderr.write(
          `--tier ${opts.tier} is not supported by 'agentlock signer enroll'.\n` +
            `currently supported: totp, os-keychain (macOS).\n` +
            `Hardware-key (YubiKey) tiers are on the roadmap; see\n` +
            `https://openagentlock.github.io/OpenAgentLock/guide/signers/\n`,
        );
        process.exit(2);
      }
      if (opts.tier === "totp" && !opts.passphrase) {
        process.stderr.write(
          `--passphrase <pp> is required for --tier totp (it seals the signing key on disk).\n`,
        );
        process.exit(2);
      }
      let ttlSeconds: number | undefined;
      if (opts.ttl) {
        if (opts.tier !== "os-keychain") {
          process.stderr.write(`--ttl is only valid with --tier os-keychain.\n`);
          process.exit(2);
        }
        try {
          ttlSeconds = parseDurationSeconds(opts.ttl);
        } catch (err) {
          process.stderr.write(`invalid --ttl: ${(err as Error).message}\n`);
          process.exit(2);
        }
      }
      await runSignerEnroll({
        tier: opts.tier as "totp" | "os-keychain",
        passphrase: opts.passphrase,
        label: opts.label,
        issuer: opts.issuer,
        ttlSeconds,
        json: opts.json,
      });
    },
  );

// Parse Go-style durations like "30m", "4h", "7d", "1h30m", "90s".
function parseDurationSeconds(input: string): number {
  const trimmed = input.replace(/\s+/g, "");
  const matches = [...trimmed.matchAll(/(\d+)(s|m|h|d)/g)];
  let total = 0;
  let consumed = 0;
  for (const m of matches) {
    consumed += m[0].length;
    const n = parseInt(m[1]!, 10);
    switch (m[2]) {
      case "s":
        total += n;
        break;
      case "m":
        total += n * 60;
        break;
      case "h":
        total += n * 3600;
        break;
      case "d":
        total += n * 86400;
        break;
    }
  }
  if (total === 0 || consumed !== trimmed.length) {
    throw new Error(`unrecognized duration "${input}" (try "30m", "4h", "7d")`);
  }
  return total;
}

program
  .command("fake-hook")
  .description(
    "Simulate an agent-harness tool-call hook and POST it to /v1/gates/check. Dev/demo only; does not wire a real harness.",
  )
  .requiredOption("--session <id>", "Session ID returned by `agentlock session create`.")
  .option("--source <name>", "Harness id (claude-code, cursor, codex, ...).", "claude-code")
  .requiredOption("--tool <name>", "Tool name (Bash, Read, Write, mcp__X__Y).")
  .option("--command <cmd>", "Bash command (shorthand for --input.command).")
  .option("--file-path <path>", "File path (shorthand for --input.file_path).")
  .option("--cwd <path>", "Working directory for scoped policy resolution.")
  .option("--input <json>", "Raw tool input as JSON.")
  .option("--url <url>", "Control-plane base URL.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      session: string;
      source: string;
      tool: string;
      command?: string;
      filePath?: string;
      cwd?: string;
      input?: string;
      url?: string;
      json: boolean;
    }) => {
      await runFakeHook({
        session: opts.session,
        source: opts.source,
        tool: opts.tool,
        command: opts.command,
        filePath: opts.filePath,
        cwd: opts.cwd,
        inputJson: opts.input,
        url: opts.url,
        json: opts.json,
      });
    },
  );

const ledger = program
  .command("ledger")
  .description("Query the local Merkle ledger.");

ledger
  .command("root")
  .description("GET /v1/ledger/root — current Merkle root over all leaves.")
  .option("--url <url>", "Control-plane base URL.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { url?: string; json: boolean }) => {
    await runLedgerRoot(opts);
  });

ledger
  .command("verify")
  .description("POST /v1/ledger/verify — replay and check the chain.")
  .option("--url <url>", "Control-plane base URL.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { url?: string; json: boolean }) => {
    await runLedgerVerify(opts);
  });

const rules = program
  .command("rules")
  .description(
    "Browse and install community rules from the openagentlock/rules registry " +
      "(or any compatible git repo). Each install POSTs the rule's gate block " +
      "to the daemon's /v1/policy/gates/yaml endpoint.",
  );

rules
  .command("add <git-url>")
  .description("Register an additional rules registry. Default upstream is openagentlock/rules.")
  .option("--name <id>", "Local registry id (defaults to a slug derived from the git URL).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (gitUrl: string, opts: { name?: string; json: boolean }) => {
    await runRulesAdd({ url: gitUrl, name: opts.name, json: opts.json });
  });

rules
  .command("sources")
  .description("List configured rules registries (clones live under $AGENTLOCK_HOME/registries/).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { json: boolean }) => {
    await runRulesSources({ json: opts.json });
  });

rules
  .command("sync")
  .description(
    "Clone or fast-forward each registered registry to its remote HEAD. " +
      "Auto-registers openagentlock/rules on first use.",
  )
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (opts: { json: boolean }) => {
    await runRulesSync({ json: opts.json });
  });

rules
  .command("search [query]")
  .description("Grep across rule.yaml files in every synced registry.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (query: string | undefined, opts: { json: boolean }) => {
    await runRulesSearch({ query, json: opts.json });
  });

rules
  .command("install <ruleId>")
  .description(
    "Install a rule into the local policy. Accepts a bare id or 'registryId:ruleId' to disambiguate.",
  )
  .option("--replace", "Overwrite an existing gate with the same id.")
  .option("--repo", "Write the rule into the current repo's .agentlock.yaml instead of daemon policy.")
  .option("--url <url>", "Control-plane base URL.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (ruleId: string, opts: { replace?: boolean; repo?: boolean; url?: string; json: boolean }) => {
    await runRulesInstall({ spec: ruleId, replace: opts.replace, repo: opts.repo, url: opts.url, json: opts.json });
  });

rules
  .command("uninstall <gateId>")
  .description("Remove an installed gate from the local policy.")
  .option("--url <url>", "Control-plane base URL.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (gateId: string, opts: { url?: string; json: boolean }) => {
    await runRulesUninstall({ id: gateId, url: opts.url, json: opts.json });
  });

rules
  .command("remove <registryId>")
  .description("Drop a registry locally — does not touch the daemon's installed gates.")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(async (registryId: string, opts: { json: boolean }) => {
    await runRulesRemove({ id: registryId, json: opts.json });
  });

// `agentlock hook <harness> <event>` — shim spawned by command-hook
// harnesses (Codex, Cursor). Reads stdin JSON, POSTs to the daemon,
// translates the response into the harness-specific output shape.
const hook = program.command("hook").description("Harness-shim subcommands.");
const hookCodex = hook
  .command("codex <event>")
  .description(
    "Codex CLI shim. Reads stdin hook payload, forwards to /v1/hooks/codex/<event>, maps allow/deny → exit 0/2.",
  )
  .allowUnknownOption()
  .action(async (event: string) => {
    await runHookCodex([event]);
  });
// commander binds the positional event above; nothing else to wire.
void hookCodex;

const hookCodexDesktop = hook
  .command("codex-desktop <event>")
  .description(
    "Codex Desktop shim. Reads stdin hook payload, forwards to /v1/hooks/codex-desktop/<event>, maps allow/deny → exit 0/2.",
  )
  .allowUnknownOption()
  .action(async (event: string) => {
    await runHookCodex([event], "codex-desktop");
  });
void hookCodexDesktop;

const hookCodexAuto = hook
  .command("codex-auto <event>")
  .description(
    "Shared Codex shim. Routes Desktop-originated hooks to codex-desktop and CLI hooks to codex.",
  )
  .allowUnknownOption()
  .action(async (event: string) => {
    await runHookCodex([event], "codex-auto");
  });
void hookCodexAuto;

const hookCursor = hook
  .command("cursor <event>")
  .description(
    "Cursor IDE shim. Reads stdin hook payload, forwards to /v1/hooks/cursor/<event>, emits {permission, agent_message?} on stdout + exit 0/2.",
  )
  .allowUnknownOption()
  .action(async (event: string) => {
    await runHookCursor([event]);
  });
void hookCursor;

const hookGemini = hook
  .command("gemini <event>")
  .description(
    "Gemini CLI shim. Reads stdin hook payload, forwards to /v1/hooks/gemini/<event>, maps allow/deny → exit 0/2 (deny also writes {decision,reason} JSON to stdout).",
  )
  .allowUnknownOption()
  .action(async (event: string) => {
    await runHookGemini([event]);
  });
void hookGemini;

const hookClaudeCode = hook
  .command("claude-code <event>")
  .description(
    "Claude Code shim. Reads stdin hook payload, forwards to /v1/hooks/claude-code/<event>, maps allow/deny → exit 0/2.",
  )
  .allowUnknownOption()
  .action(async (event: string) => {
    await runHookClaudeCode([event]);
  });
void hookClaudeCode;

// `agentlock mcp-server` — MCP stdio server spawned by Claude Desktop.
// Claude Desktop has no PreToolUse/PostToolUse surface, so this is the
// only honest install: register agentlock as an MCP server, expose
// read-only observability tools (status, recent ledger entries) backed
// by the daemon. No enforcement on Desktop's built-in tools.
program
  .command("mcp-server")
  .description(
    "Run the OpenAgentLock MCP stdio server. Spawned by Claude Desktop after `agentlock install` registers it under mcpServers. Exposes read-only status + ledger query tools.",
  )
  .action(async () => {
    await runMcpServer();
  });

// `agentlock mcp-proxy --name <id> -- <child-cmd> [args...]`
//
// Stdio bridge spawned by Claude Desktop in place of each user-installed
// MCP server (`agentlock install` rewrites their claude_desktop_config.json
// to point here, preserving the original command under _agentlock_original).
// Pumps bytes both directions verbatim except for tools/call requests,
// which it forwards to /v1/hooks/claude-desktop/pre-tool-use for policy
// evaluation. allowUnknownOption + helpOption(false) keeps commander from
// gobbling the child's flags before we see the `--` separator.
program
  .command("mcp-proxy")
  .description(
    "Stdio proxy for Claude Desktop's MCP servers. Intercepts tools/call, applies policy via the daemon, forwards or denies. Spawned by Claude Desktop after `agentlock install` wraps each user MCP server.",
  )
  .allowUnknownOption()
  .helpOption(false)
  .action(async () => {
    // Slice off "node|bun, scriptPath, mcp-proxy" — the rest are our args.
    const ix = process.argv.indexOf("mcp-proxy");
    const rest = ix >= 0 ? process.argv.slice(ix + 1) : [];
    await runMcpProxy(rest);
  });

await program.parseAsync(process.argv);
