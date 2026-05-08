import { useEffect, useState } from "react";
import { apiSend } from "@/lib/api";
import type { GateView, MatchView } from "@/lib/types";

interface RuleEditDrawerProps {
  gate: GateView | null;
  onSaved: () => void;
  onClose: () => void;
}

export function RuleEditDrawer({ gate, onSaved, onClose }: RuleEditDrawerProps) {
  const [mode, setMode] = useState<string>("inherit");
  const [disabled, setDisabled] = useState<boolean>(false);
  const [commandRegexText, setCommandRegexText] = useState<string>("");
  const [pathRegexText, setPathRegexText] = useState<string>("");
  const [urlRegexText, setUrlRegexText] = useState<string>("");
  const [testInput, setTestInput] = useState<string>("");
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!gate) return;
    const editableMatch = simpleMatch(gate);
    setMode(gate.mode || "inherit");
    setDisabled(!!gate.disabled);
    setCommandRegexText((editableMatch?.any_command_regex ?? gate.any_command_regex ?? []).join("\n"));
    setPathRegexText((editableMatch?.any_path_regex ?? gate.any_path_regex ?? []).join("\n"));
    setUrlRegexText((editableMatch?.any_url_regex ?? gate.any_url_regex ?? []).join("\n"));
    setTestInput("");
    setError(null);
  }, [gate]);

  if (!gate) {
    return (
      <aside className="oal-panel h-fit">
        <div className="text-xs text-muted">Select a rule on the left to edit it.</div>
      </aside>
    );
  }

  const onSave = async () => {
    if (!gate) return;
    setSaving(true);
    setError(null);
    try {
      const splitRegexes = (value: string) =>
        value
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const body: Record<string, unknown> = {
        disabled,
        mode,
      };
      if ((gate.match?.any_of?.length ?? 0) === 0) {
        body.any_command_regex = splitRegexes(commandRegexText);
        body.any_path_regex = splitRegexes(pathRegexText);
        body.any_url_regex = splitRegexes(urlRegexText);
      }
      await apiSend(`/v1/policy/gates/${encodeURIComponent(gate.id)}`, "PATCH", body);
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const groupedMatch = (gate.match?.any_of?.length ?? 0) > 0;
  const matchPreview = previewMatcher(testInput, {
    command: groupedMatch
      ? flattenMatchRegexes(gate.match, "command")
      : splitLines(commandRegexText),
    path: groupedMatch ? flattenMatchRegexes(gate.match, "path") : splitLines(pathRegexText),
    url: groupedMatch ? flattenMatchRegexes(gate.match, "url") : splitLines(urlRegexText),
  });
  const displayMatch = simpleMatch(gate);

  return (
    <aside className="oal-panel h-fit">
      <div className="flex items-start justify-between mb-3">
        <div className="text-xs font-semibold uppercase tracking-wider text-muted">Edit rule</div>
        <button type="button" className="oal-btn-link" onClick={onClose}>
          close
        </button>
      </div>

      <div className="space-y-3">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted mb-1">id</div>
          <div className="text-xs font-mono text-neutral-100">{gate.id}</div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">tool</div>
            <div className="text-xs font-mono text-neutral-100">
              {displayMatch?.tool ?? gate.tool ?? "—"}
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">tool_prefix</div>
            <div className="text-xs font-mono text-neutral-100">
              {displayMatch?.tool_prefix ?? gate.tool_prefix ?? "—"}
            </div>
          </div>
        </div>

        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted mb-1">evaluators</div>
          <div className="text-xs font-mono text-neutral-100">
            {gate.evaluators.length > 0 ? gate.evaluators.join(", ") : "—"}
          </div>
        </div>

        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted mb-1">
            match schema
          </div>
          <MatchSchemaView match={gate.match} />
        </div>

        <div>
          <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
            any_command_regex (one per line)
          </label>
          <textarea
            className="oal-input w-full font-mono min-h-[96px]"
            value={commandRegexText}
            onChange={(e) => setCommandRegexText(e.target.value)}
            disabled={groupedMatch}
          />
        </div>

        <div>
          <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
            any_path_regex (one per line)
          </label>
          <textarea
            className="oal-input w-full font-mono min-h-[72px]"
            value={pathRegexText}
            onChange={(e) => setPathRegexText(e.target.value)}
            disabled={groupedMatch}
          />
        </div>

        <div>
          <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
            any_url_regex (one per line)
          </label>
          <textarea
            className="oal-input w-full font-mono min-h-[72px]"
            value={urlRegexText}
            onChange={(e) => setUrlRegexText(e.target.value)}
            disabled={groupedMatch}
          />
        </div>

        {groupedMatch && (
          <div className="text-[11px] text-muted">
            This rule uses grouped match branches. Inline regex editing is available for simple
            top-level matchers; delete + re-add grouped rules to change branch structure.
          </div>
        )}

        <div className="border-t border-border pt-3">
          <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
            test input against this rule
          </label>
          <textarea
            className="oal-input w-full font-mono min-h-[72px]"
            value={testInput}
            onChange={(e) => setTestInput(e.target.value)}
            placeholder="Paste a command, path, or URL"
          />
          <div
            className={`mt-2 text-xs ${
              matchPreview?.matched ? "text-deny" : "text-muted"
            }`}
          >
            {matchPreview?.message ?? "Enter a value to check local regex match."}
          </div>
        </div>

        <div>
          <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
            mode
          </label>
          <select
            className="oal-input w-full"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
          >
            <option value="inherit">inherit</option>
            <option value="monitor">monitor</option>
            <option value="enforce">enforce</option>
          </select>
        </div>

        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={!disabled}
            onChange={(e) => setDisabled(!e.target.checked)}
          />
          enabled
        </label>

        {error && <div className="text-xs text-deny">{error}</div>}

        <div className="flex gap-2">
          <button type="button" className="oal-btn" onClick={onSave} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button type="button" className="oal-btn" onClick={onClose}>
            Cancel
          </button>
        </div>

        <div className="text-[11px] text-muted pt-2 border-t border-border">
          Tool, tool_prefix, and evaluator shape are not yet editable inline — delete + re-add to
          change those.
        </div>
      </div>
    </aside>
  );
}

function splitLines(value: string): string[] {
  return value
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function simpleMatch(gate: GateView): MatchView | undefined {
  if (gate.match && (gate.match.any_of?.length ?? 0) === 0) return gate.match;
  return undefined;
}

function MatchSchemaView({ match }: { match?: MatchView }) {
  if (!match) {
    return <div className="text-xs text-muted">—</div>;
  }
  const branches =
    match.any_of && match.any_of.length > 0
      ? match.any_of.map((sub, index) => ({ match: sub, label: `any_of[${index}]` }))
      : [{ match, label: "match" }];
  return (
    <div className="space-y-2">
      {branches.map(({ match: branch, label }) => (
        <div
          key={label}
          className="rounded border border-border bg-neutral-950/30 p-2 text-[11px] font-mono"
        >
          <div className="mb-1 text-muted">{label}</div>
          <MatchLine label="tool" value={branch.tool} />
          <MatchLine label="tool_prefix" value={branch.tool_prefix} />
          <MatchLine label="path_glob_regex" value={branch.path_glob_regex} />
          <MatchList label="any_command_regex" values={branch.any_command_regex} />
          <MatchList label="any_path_regex" values={branch.any_path_regex} />
          <MatchList label="any_url_regex" values={branch.any_url_regex} />
        </div>
      ))}
    </div>
  );
}

function MatchLine({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div>
      <span className="text-muted">{label}: </span>
      <span>{value}</span>
    </div>
  );
}

function MatchList({ label, values }: { label: string; values?: string[] }) {
  if (!values || values.length === 0) return null;
  return (
    <div>
      <div className="text-muted">{label}:</div>
      {values.map((value, index) => (
        <div key={`${label}-${index}`} className="pl-3">
          {value}
        </div>
      ))}
    </div>
  );
}

function flattenMatchRegexes(
  match: MatchView | undefined,
  kind: "command" | "path" | "url",
): string[] {
  if (!match) return [];
  const field =
    kind === "command"
      ? "any_command_regex"
      : kind === "path"
        ? "any_path_regex"
        : "any_url_regex";
  return [
    ...(match[field] ?? []),
    ...((match.any_of ?? []).flatMap((sub) => flattenMatchRegexes(sub, kind))),
  ];
}

function previewMatcher(
  value: string,
  regexes: { command: string[]; path: string[]; url: string[] },
): { matched: boolean; message: string } | null {
  const input = value.trim();
  if (!input) return null;
  const groups: Array<[string, string[]]> = [
    ["command", regexes.command],
    ["path", regexes.path],
    ["url", regexes.url],
  ];
  for (const [label, list] of groups) {
    for (const pattern of list) {
      try {
        if (new RegExp(pattern).test(input)) {
          return { matched: true, message: `matches ${label} regex: ${pattern}` };
        }
      } catch (err) {
        return {
          matched: false,
          message: `invalid ${label} regex ${pattern}: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }
    }
  }
  return { matched: false, message: "no regex match for this input" };
}
