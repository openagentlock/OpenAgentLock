import { describe, expect, test } from "bun:test";
import {
  isOutcomeEntry,
  outcomeByToolUseId,
  subjectFromLedgerEntry,
} from "../src/lib/ledgerEntryDisplay";
import type { LedgerEntry } from "../src/lib/types";

const baseEntry: LedgerEntry = {
  seq: 7,
  ts: "2026-05-08T00:00:00Z",
  source: "codex",
  tool_use_id: "call_123",
  signer: "none",
  payload_hash: "payload",
  sig: "",
  leaf_hash: "leaf",
  prev_leaf: "prev",
};

describe("subjectFromLedgerEntry", () => {
  test("prefers shell command input", () => {
    expect(
      subjectFromLedgerEntry({
        ...baseEntry,
        input: { command: "rm -rf /tmp/nops" },
      }),
    ).toEqual({ label: "command", value: "rm -rf /tmp/nops" });
  });

  test("falls back to file path input", () => {
    expect(
      subjectFromLedgerEntry({
        ...baseEntry,
        input: { file_path: "/tmp/demo/.env" },
      }),
    ).toEqual({ label: "path", value: "/tmp/demo/.env" });
  });

  test("falls back to URL input", () => {
    expect(
      subjectFromLedgerEntry({
        ...baseEntry,
        tool_input: { url: "https://example.test/a" },
      }),
    ).toEqual({ label: "url", value: "https://example.test/a" });
  });

  test("returns null when no displayable input is present", () => {
    expect(subjectFromLedgerEntry(baseEntry)).toBeNull();
  });
});

describe("outcome helpers", () => {
  test("identifies post-tool outcomes", () => {
    expect(isOutcomeEntry({ ...baseEntry, verdict: "complete" })).toBe(true);
    expect(isOutcomeEntry({ ...baseEntry, verdict: "failure" })).toBe(true);
    expect(isOutcomeEntry({ ...baseEntry, verdict: "allow" })).toBe(false);
  });

  test("indexes the latest outcome by tool_use_id", () => {
    const newer = { ...baseEntry, seq: 9, verdict: "failure" };
    expect(
      outcomeByToolUseId([
        { ...baseEntry, seq: 1, verdict: "allow" },
        { ...baseEntry, seq: 8, verdict: "complete" },
        newer,
      ]).get("call_123"),
    ).toEqual(newer);
  });
});
