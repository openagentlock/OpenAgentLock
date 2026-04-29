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
import { runHookCodex } from "./commands/hook-codex.ts";
import { runLedgerRoot, runLedgerVerify } from "./commands/ledger.ts";
import { runSignerEnroll } from "./commands/signer-enroll.ts";

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
  .option("--code <6-digit>", "TOTP code (required for --tier totp).")
  .option("--passphrase <pp>", "TOTP passphrase (required for --tier totp).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      tier: string;
      url?: string;
      policyHash?: string;
      code?: string;
      passphrase?: string;
      json: boolean;
    }) => {
      if (opts.tier !== "software" && opts.tier !== "totp") {
        process.stderr.write(`tier ${opts.tier} not wired yet (MVP supports software | totp)\n`);
        process.exit(2);
      }
      if (opts.tier === "totp" && (!opts.code || !opts.passphrase)) {
        process.stderr.write(`--tier totp requires --code and --passphrase\n`);
        process.exit(2);
      }
      await runSessionCreate({
        tier: opts.tier as "software" | "totp",
        url: opts.url,
        json: opts.json,
        policyHash: opts.policyHash,
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
  .option("--code <6-digit>", "TOTP code (required for --tier totp).")
  .option("--passphrase <pp>", "TOTP passphrase (required for --tier totp).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      id: string;
      tier: string;
      url?: string;
      policyHash?: string;
      code?: string;
      passphrase?: string;
      json: boolean;
    }) => {
      if (opts.tier !== "software" && opts.tier !== "totp") {
        process.stderr.write(`tier ${opts.tier} not wired yet\n`);
        process.exit(2);
      }
      if (opts.tier === "totp" && (!opts.code || !opts.passphrase)) {
        process.stderr.write(`--tier totp requires --code and --passphrase\n`);
        process.exit(2);
      }
      await runSessionRotate({
        id: opts.id,
        tier: opts.tier as "software" | "totp",
        url: opts.url,
        json: opts.json,
        policyHash: opts.policyHash,
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
  .description("Enroll a signer tier. MVP supports totp.")
  .requiredOption("--tier <tier>", "Signer tier (totp).")
  .option("--passphrase <pp>", "Passphrase used to seal the signing key (required for totp).")
  .option("--label <label>", "otpauth label (default: agentlock).")
  .option("--issuer <issuer>", "otpauth issuer (default: OpenAgentLock).")
  .option("--json", "Emit JSON instead of human output.", false)
  .action(
    async (opts: {
      tier: string;
      passphrase?: string;
      label?: string;
      issuer?: string;
      json: boolean;
    }) => {
      if (opts.tier !== "totp") {
        process.stderr.write(`tier ${opts.tier} not wired yet (MVP supports totp)\n`);
        process.exit(2);
      }
      if (!opts.passphrase) {
        process.stderr.write(`--passphrase is required for --tier totp\n`);
        process.exit(2);
      }
      await runSignerEnroll({
        tier: "totp",
        passphrase: opts.passphrase,
        label: opts.label,
        issuer: opts.issuer,
        json: opts.json,
      });
    },
  );

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

// `agentlock hook codex <event>` — shim spawned by Codex CLI's
// command-hooks. Reads stdin JSON, POSTs to the daemon, exits 0/2.
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

await program.parseAsync(process.argv);
