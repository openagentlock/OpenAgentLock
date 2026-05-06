import type { AddRuleInitialPreset } from "@/lib/rulePresetTypes";
import type { LedgerEntry } from "@/lib/types";

function stringField(input: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return null;
}

function escapeRegexLiteral(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function exactRegex(value: string): string {
  return `^${escapeRegexLiteral(value)}$`;
}

export function rulePresetFromLedgerEntry(entry: LedgerEntry): AddRuleInitialPreset | null {
  const input = entry.input ?? entry.tool_input;
  if (!input) return null;

  const command = stringField(input, ["command"]);
  if (command) {
    return {
      ruleType: "bash",
      id: `dashboard.block-${entry.seq}`,
      tool: entry.tool || "Bash",
      commandRegexes: exactRegex(command),
      action: "deny",
      mode: "inherit",
    };
  }

  const path = stringField(input, ["file_path", "path"]);
  if (path) {
    return {
      ruleType: "secret-read",
      id: `dashboard.block-${entry.seq}`,
      tool: entry.tool || "Read",
      pathRegexes: exactRegex(path),
      action: "deny",
      mode: "inherit",
    };
  }

  const url = stringField(input, ["url"]);
  if (url) {
    return {
      ruleType: "net-egress-url",
      id: `dashboard.block-${entry.seq}`,
      tool: entry.tool || "WebFetch",
      urlRegexes: exactRegex(url),
      action: "deny",
      mode: "inherit",
    };
  }

  return null;
}
