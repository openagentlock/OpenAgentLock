import { describe, expect, test } from "bun:test";
import { rulePresetFromLedgerEntry } from "../src/lib/eventRulePreset";
import type { LedgerEntry } from "../src/lib/types";

const baseEntry: LedgerEntry = {
  seq: 42,
  ts: "2026-05-06T00:00:00Z",
  source: "codex",
  tool_use_id: "toolu_123",
  signer: "none",
  payload_hash: "hash",
  sig: "",
  leaf_hash: "leaf",
  prev_leaf: "prev",
};

describe("rulePresetFromLedgerEntry", () => {
  test("returns null when a ledger row does not include tool input", () => {
    expect(rulePresetFromLedgerEntry(baseEntry)).toBeNull();
  });

  test("builds an exact Bash command preset from row input", () => {
    expect(
      rulePresetFromLedgerEntry({
        ...baseEntry,
        tool: "Bash",
        input: { command: "rm -rf /tmp/demo" },
      }),
    ).toEqual({
      ruleType: "bash",
      id: "dashboard.block-42",
      tool: "Bash",
      commandRegexes: "^rm -rf /tmp/demo$",
      action: "deny",
      mode: "inherit",
    });
  });

  test("builds an exact path preset from file_path", () => {
    expect(
      rulePresetFromLedgerEntry({
        ...baseEntry,
        tool: "Read",
        input: { file_path: "/tmp/demo/.env" },
      }),
    ).toMatchObject({
      ruleType: "secret-read",
      tool: "Read",
      pathRegexes: "^/tmp/demo/\\.env$",
    });
  });

  test("builds an exact URL preset from url", () => {
    expect(
      rulePresetFromLedgerEntry({
        ...baseEntry,
        tool: "WebFetch",
        input: { url: "https://attacker.example/a?x=1" },
      }),
    ).toMatchObject({
      ruleType: "net-egress-url",
      tool: "WebFetch",
      urlRegexes: "^https://attacker\\.example/a\\?x=1$",
    });
  });
});
