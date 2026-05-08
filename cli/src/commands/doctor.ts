import { existsSync } from "node:fs";
import { join } from "node:path";

import { detectAll, type Detection } from "../detect/index.ts";
import { apiClient } from "../util/api.ts";
import { binDir } from "../util/paths.ts";

type CheckStatus = "ok" | "warn" | "error";

interface DoctorCheck {
  code: string;
  status: CheckStatus;
  message: string;
  detail?: string;
}

interface DoctorHarness {
  id: string;
  name: string;
  detected: boolean;
  wired: boolean;
  daemon_url?: string;
  evidence: string[];
  notes: string[];
}

interface DoctorReport {
  cli_version: string;
  daemon: {
    base_url: string;
    reachable: boolean;
    status?: string;
    error?: string;
  };
  ledger?: {
    ok: boolean;
    count: number;
    root?: string;
    first_bad_at?: number;
    reason?: string;
  };
  mode?: {
    mode: string;
  };
  policy?: {
    hash: string;
    gates: number;
    daemon_mode: string;
    policy_mode: string;
  };
  sessions?: {
    total: number;
    active: number;
    live_policy_hash: string;
  };
  harnesses: DoctorHarness[];
  checks: DoctorCheck[];
  summary: Record<CheckStatus, number>;
}

interface DoctorOptions {
  url?: string;
  json: boolean;
  version: string;
}

const SUPPORTED_HARNESSES = new Set([
  "claude-code",
  "claude-desktop",
  "codex",
  "codex-desktop",
  "cursor",
  "gemini",
]);

export async function runDoctor(opts: DoctorOptions): Promise<void> {
  const report = await collectDoctorReport({
    url: opts.url,
    version: opts.version,
  });

  if (opts.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    process.stdout.write(renderDoctorReport(report));
  }

  if (report.summary.error > 0) {
    process.exitCode = 1;
  }
}

export async function collectDoctorReport(opts: {
  url?: string;
  version: string;
}): Promise<DoctorReport> {
  const client = apiClient(opts.url);
  const checks: DoctorCheck[] = [];
  const harnessDetections = await detectAll();
  const harnesses = harnessDetections.map(toDoctorHarness);

  const wrapper = join(binDir(), "agentlock");
  checks.push(
    existsSync(wrapper)
      ? {
          code: "wrapper.installed",
          status: "ok",
          message: "stable hook wrapper exists",
          detail: wrapper,
        }
      : {
          code: "wrapper.missing",
          status: "warn",
          message: "stable hook wrapper is missing; run agentlock install to create it",
          detail: wrapper,
        },
  );

  const installedHarnesses = harnessDetections.filter((h) => h.installed);
  if (installedHarnesses.length === 0) {
    checks.push({
      code: "harness.none_detected",
      status: "warn",
      message: "no installed agent harnesses detected",
    });
  }
  for (const h of installedHarnesses) {
    if (!SUPPORTED_HARNESSES.has(h.id)) continue;
    if (h.agentlockInstalled) {
      const wiredURL = h.agentlockDaemonURL ? originOf(h.agentlockDaemonURL) : undefined;
      checks.push({
        code: `harness.${h.id}.wired`,
        status: "ok",
        message: `${h.displayName} is wired to OpenAgentLock`,
        detail: wiredURL,
      });
      if (wiredURL && wiredURL !== originOf(client.baseUrl)) {
        checks.push({
          code: `harness.${h.id}.daemon_mismatch`,
          status: "warn",
          message: `${h.displayName} is wired to a different daemon than doctor is checking`,
          detail: `wired=${wiredURL} checked=${originOf(client.baseUrl)}`,
        });
      }
    } else {
      checks.push({
        code: `harness.${h.id}.not_wired`,
        status: "warn",
        message: `${h.displayName} is installed but not wired to OpenAgentLock`,
        detail: "run agentlock install",
      });
    }
  }

  const daemon: DoctorReport["daemon"] = {
    base_url: client.baseUrl,
    reachable: false,
  };

  let ledger: DoctorReport["ledger"];
  let mode: DoctorReport["mode"];
  let policy: DoctorReport["policy"];
  let sessions: DoctorReport["sessions"];

  try {
    const health = await client.health();
    daemon.reachable = true;
    daemon.status = health.status;
    checks.push({
      code: "daemon.reachable",
      status: "ok",
      message: `daemon reachable at ${client.baseUrl}`,
      detail: health.status,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    daemon.error = message;
    checks.push({
      code: "daemon.unreachable",
      status: "error",
      message: `daemon unreachable at ${client.baseUrl}`,
      detail: message,
    });
  }

  if (daemon.reachable) {
    try {
      const result = await client.ledgerVerify();
      ledger = {
        ok: result.ok,
        count: result.count,
        root: result.root,
        first_bad_at: result.first_bad_at,
        reason: result.reason,
      };
      checks.push({
        code: "ledger.verify",
        status: result.ok ? "ok" : "error",
        message: result.ok
          ? `ledger verifies (${result.count} entries)`
          : "ledger verification failed",
        detail: result.reason,
      });
    } catch (err) {
      checks.push({
        code: "ledger.verify_error",
        status: "error",
        message: "ledger verification endpoint failed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    try {
      const gotMode = await client.getMode();
      mode = { mode: gotMode.mode };
      checks.push({
        code: "daemon.mode",
        status: "ok",
        message: `daemon mode is ${gotMode.mode}`,
      });
    } catch (err) {
      checks.push({
        code: "daemon.mode_error",
        status: "warn",
        message: "could not read daemon mode",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    try {
      const view = await client.policyView();
      policy = {
        hash: view.hash,
        gates: view.gates.length,
        daemon_mode: view.daemon_mode,
        policy_mode: view.policy_mode,
      };
      checks.push({
        code: "policy.loaded",
        status: "ok",
        message: `policy loaded (${view.gates.length} gates)`,
        detail: view.hash,
      });
    } catch (err) {
      checks.push({
        code: "policy.view_error",
        status: "warn",
        message: "could not read policy view",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    try {
      const list = await client.listSessions();
      const active = list.sessions.filter((s) => s.active).length;
      sessions = {
        total: list.sessions.length,
        active,
        live_policy_hash: list.live_policy_hash,
      };
      checks.push({
        code: "sessions.list",
        status: "ok",
        message: `${active} active session(s), ${list.sessions.length} total`,
      });
    } catch (err) {
      checks.push({
        code: "sessions.list_error",
        status: "warn",
        message: "could not list sessions",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const summary: Record<CheckStatus, number> = { ok: 0, warn: 0, error: 0 };
  for (const check of checks) summary[check.status]++;

  return {
    cli_version: opts.version,
    daemon,
    ledger,
    mode,
    policy,
    sessions,
    harnesses,
    checks,
    summary,
  };
}

function toDoctorHarness(d: Detection): DoctorHarness {
  return {
    id: d.id,
    name: d.displayName,
    detected: d.installed,
    wired: d.agentlockInstalled === true,
    daemon_url: d.agentlockDaemonURL,
    evidence: d.evidence,
    notes: d.notes,
  };
}

function originOf(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return value;
  }
}

export function renderDoctorReport(report: DoctorReport): string {
  const lines: string[] = [];
  lines.push("OpenAgentLock doctor");
  lines.push(`  cli: ${report.cli_version}`);
  lines.push(`  daemon: ${report.daemon.base_url}`);
  lines.push("");
  lines.push("Checks");
  for (const check of report.checks) {
    lines.push(`  ${mark(check.status)} ${check.message}`);
    if (check.detail) lines.push(`      ${check.detail}`);
  }
  lines.push("");
  lines.push("Harnesses");
  for (const h of report.harnesses) {
    const state = h.detected ? (h.wired ? "wired" : "detected") : "not detected";
    const suffix = h.daemon_url ? ` -> ${h.daemon_url}` : "";
    lines.push(`  ${h.detected && h.wired ? "OK" : h.detected ? "!!" : "--"} ${h.name}: ${state}${suffix}`);
  }
  lines.push("");
  lines.push(
    `Summary: ${report.summary.ok} ok, ${report.summary.warn} warning(s), ${report.summary.error} error(s)`,
  );
  return lines.join("\n") + "\n";
}

function mark(status: CheckStatus): string {
  if (status === "ok") return "OK";
  if (status === "warn") return "!!";
  return "XX";
}
