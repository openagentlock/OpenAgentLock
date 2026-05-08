// `agentlock rules ...` unit tests. The daemon-facing install/uninstall
// paths are exercised against a tiny in-process HTTP fake so we don't
// have to bring up the real control-plane just to verify the CLI's wire
// shape. Registry plumbing (clone/pull) needs git, so we build a fake
// "registry" by hand-constructing the on-disk layout the CLI expects.

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  runRulesInstall,
  runRulesRemove,
  runRulesSearch,
  runRulesSources,
  runRulesUninstall,
} from "../src/commands/rules";

interface CapturedRequest {
  url: string;
  method: string;
  body: unknown;
}

async function withFakeDaemon<T>(
  responses: { path: RegExp; status: number; body: unknown }[],
  fn: (url: string, captured: CapturedRequest[]) => Promise<T>,
): Promise<T> {
  const captured: CapturedRequest[] = [];
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      const body = req.method === "POST" || req.method === "PATCH" ? await req.text() : "";
      captured.push({
        url: url.pathname,
        method: req.method,
        body: body ? JSON.parse(body) : null,
      });
      for (const r of responses) {
        if (r.path.test(url.pathname)) {
          return new Response(JSON.stringify(r.body), {
            status: r.status,
            headers: { "content-type": "application/json" },
          });
        }
      }
      return new Response("not found", { status: 404 });
    },
  });
  try {
    return await fn(`http://127.0.0.1:${server.port}`, captured);
  } finally {
    server.stop(true);
  }
}

function seedRegistry(home: string, registryId: string, ruleYAMLs: { dir: string; yaml: string }[]) {
  const root = join(home, "registries", registryId, "rules");
  mkdirSync(root, { recursive: true });
  for (const r of ruleYAMLs) {
    const dir = join(root, r.dir);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "rule.yaml"), r.yaml);
  }
  const registriesPath = join(home, "registries.json");
  // Merge with any pre-existing registries.json so multiple calls
  // accumulate registries instead of overwriting each other.
  let existing: { schema_version: 1; registries: { id: string; url: string; added_at: string }[] } = {
    schema_version: 1,
    registries: [],
  };
  if (existsSync(registriesPath)) {
    existing = JSON.parse(readFileSync(registriesPath, "utf8"));
  }
  if (!existing.registries.some((r) => r.id === registryId)) {
    existing.registries.push({
      id: registryId,
      url: "https://example.com/fake.git",
      added_at: new Date().toISOString(),
    });
  }
  writeFileSync(registriesPath, JSON.stringify(existing, null, 2));
}

const SAMPLE_RULE = `schema_version: 1
id: rogue.destructive-bash
name: Block destructive shell commands
description: A bare-bones test rule.
severity: high
tags: [bash, destructive]
gate:
  match:
    tool: Bash
    any_command_regex:
      - 'rm\\s+-rf\\s+/'
  evaluate:
    - kind: always
      action: deny
`;

const ALT_RULE = `schema_version: 1
id: exfil.curl-with-env
name: Block curl exfiltration
description: Another test rule.
severity: critical
tags: [exfil]
gate:
  match:
    tool: Bash
    any_command_regex:
      - 'curl[^|]*\\$'
  evaluate:
    - kind: always
      action: deny
`;

describe("agentlock rules", () => {
  let home: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentlock-rules-"));
    originalHome = process.env.AGENTLOCK_HOME;
    process.env.AGENTLOCK_HOME = home;
    seedRegistry(home, "openagentlock-rules", [
      { dir: "destructive-bash", yaml: SAMPLE_RULE },
      { dir: "curl-with-env", yaml: ALT_RULE },
    ]);
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    if (originalHome === undefined) delete process.env.AGENTLOCK_HOME;
    else process.env.AGENTLOCK_HOME = originalHome;
  });

  test("search returns matching rules", async () => {
    const captured: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((s: string) => {
      captured.push(s);
      return true;
    }) as typeof process.stdout.write;
    try {
      await runRulesSearch({ query: "exfil" });
    } finally {
      process.stdout.write = origWrite;
    }
    const out = captured.join("");
    expect(out).toContain("exfil.curl-with-env");
    expect(out).not.toContain("rogue.destructive-bash");
  });

  test("install POSTs YAML body to /v1/policy/gates/yaml", async () => {
    await withFakeDaemon(
      [
        {
          path: /\/v1\/policy\/gates\/yaml/,
          status: 201,
          body: { hash: "sha256:abcd", gates: 1, id: "rogue.destructive-bash", needs_reload: true },
        },
      ],
      async (url, captured) => {
        await runRulesInstall({ spec: "rogue.destructive-bash", url, json: true });
        expect(captured.length).toBe(1);
        expect(captured[0]!.method).toBe("POST");
        expect(captured[0]!.url).toBe("/v1/policy/gates/yaml");
        const body = captured[0]!.body as { yaml: string; replace: boolean };
        expect(body.replace).toBe(false);
        expect(body.yaml).toContain("rogue.destructive-bash");
        expect(body.yaml).toContain("registry:openagentlock-rules");
        expect(body.yaml).toContain("any_command_regex");
        expect(body.yaml).toContain("rm");
      },
    );
  });

  test("install --replace forwards the flag", async () => {
    await withFakeDaemon(
      [
        {
          path: /\/v1\/policy\/gates\/yaml/,
          status: 201,
          body: { hash: "sha256:1", gates: 1, id: "rogue.destructive-bash", needs_reload: true },
        },
      ],
      async (url, captured) => {
        await runRulesInstall({
          spec: "rogue.destructive-bash",
          replace: true,
          url,
          json: true,
        });
        const body = captured[0]!.body as { replace: boolean };
        expect(body.replace).toBe(true);
      },
    );
  });

  test("install --repo writes registry rule gate into .agentlock.yaml", async () => {
    const repo = join(home, "repo");
    mkdirSync(repo, { recursive: true });
    const originalCwd = process.cwd();
    process.chdir(repo);
    try {
      await runRulesInstall({
        spec: "rogue.destructive-bash",
        repo: true,
        json: true,
      });
    } finally {
      process.chdir(originalCwd);
    }

    const body = readFileSync(join(repo, ".agentlock.yaml"), "utf8");
    expect(body).toContain("version: 1");
    expect(body).toContain("rogue.destructive-bash");
    expect(body).toContain("registry:openagentlock-rules");
    expect(body).toContain("any_command_regex");
    expect(body).toContain("rm");
  });

  test("install on missing rule throws", async () => {
    await expect(runRulesInstall({ spec: "nonexistent.id", url: "http://0" })).rejects.toThrow(
      /not found/,
    );
  });

  test("install with registryId:ruleId form scopes the lookup", async () => {
    seedRegistry(home, "another-tap", [{ dir: "destructive-bash", yaml: SAMPLE_RULE }]);
    // Both registries now contain rogue.destructive-bash. Bare lookup
    // should be ambiguous; registry:id form should resolve cleanly.
    await expect(runRulesInstall({ spec: "rogue.destructive-bash", url: "http://0" })).rejects.toThrow(
      /ambiguous/,
    );

    await withFakeDaemon(
      [
        {
          path: /\/v1\/policy\/gates\/yaml/,
          status: 201,
          body: { hash: "sha256:2", gates: 1, id: "rogue.destructive-bash", needs_reload: true },
        },
      ],
      async (url) => {
        await runRulesInstall({
          spec: "another-tap:rogue.destructive-bash",
          url,
          json: true,
        });
      },
    );
  });

  test("uninstall sends DELETE to /v1/policy/gates/{id}", async () => {
    await withFakeDaemon(
      [
        {
          path: /\/v1\/policy\/gates\/[^/]+/,
          status: 200,
          body: { hash: "sha256:def", gates: 0, needs_reload: true },
        },
      ],
      async (url, captured) => {
        await runRulesUninstall({ id: "rogue.destructive-bash", url, json: true });
        expect(captured[0]!.method).toBe("DELETE");
        expect(captured[0]!.url).toBe("/v1/policy/gates/rogue.destructive-bash");
      },
    );
  });

  test("remove deletes the registry from disk + registries.json", async () => {
    expect(existsSync(join(home, "registries", "openagentlock-rules"))).toBe(true);
    await runRulesRemove({ id: "openagentlock-rules", json: true });
    expect(existsSync(join(home, "registries", "openagentlock-rules"))).toBe(false);
    const regs = JSON.parse(readFileSync(join(home, "registries.json"), "utf8"));
    expect(regs.registries).toHaveLength(0);
  });

  test("sources auto-registers upstream when no registries are configured", async () => {
    // Wipe registries to simulate a fresh install.
    rmSync(join(home, "registries.json"));
    rmSync(join(home, "registries"), { recursive: true, force: true });

    const captured: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((s: string) => {
      captured.push(s);
      return true;
    }) as typeof process.stdout.write;
    try {
      await runRulesSources({ json: false });
    } finally {
      process.stdout.write = origWrite;
    }
    const regs = JSON.parse(readFileSync(join(home, "registries.json"), "utf8"));
    expect(regs.registries[0].id).toBe("openagentlock-rules");
    expect(captured.join("")).toContain("openagentlock-rules");
  });
});
