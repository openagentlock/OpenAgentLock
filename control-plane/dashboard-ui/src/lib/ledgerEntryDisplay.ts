import type { LedgerEntry } from "@/lib/types";

export interface LedgerEntrySubject {
  label: "command" | "path" | "url";
  value: string;
}

export function isOutcomeEntry(entry: LedgerEntry): boolean {
  return entry.verdict === "complete" || entry.verdict === "failure";
}

export function outcomeByToolUseId(entries: LedgerEntry[]): Map<string, LedgerEntry> {
  const out = new Map<string, LedgerEntry>();
  for (const entry of entries) {
    if (!isOutcomeEntry(entry) || !entry.tool_use_id) continue;
    const current = out.get(entry.tool_use_id);
    if (!current || entry.seq > current.seq) {
      out.set(entry.tool_use_id, entry);
    }
  }
  return out;
}

function stringField(input: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return null;
}

export function subjectFromLedgerEntry(entry: LedgerEntry): LedgerEntrySubject | null {
  const input = entry.input ?? entry.tool_input;
  if (!input) return null;

  const command = stringField(input, ["command"]);
  if (command) return { label: "command", value: command };

  const path = stringField(input, ["file_path", "path"]);
  if (path) return { label: "path", value: path };

  const url = stringField(input, ["url"]);
  if (url) return { label: "url", value: url };

  return null;
}
