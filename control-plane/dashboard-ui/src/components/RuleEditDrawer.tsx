import { useEffect, useState } from "react";
import { apiSend } from "@/lib/api";
import type { GateView } from "@/lib/types";

interface RuleEditDrawerProps {
  gate: GateView | null;
  onSaved: () => void;
  onClose: () => void;
}

export function RuleEditDrawer({ gate, onSaved, onClose }: RuleEditDrawerProps) {
  const [mode, setMode] = useState<string>("inherit");
  const [disabled, setDisabled] = useState<boolean>(false);
  const [regexText, setRegexText] = useState<string>("");
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!gate) return;
    setMode(gate.mode || "inherit");
    setDisabled(!!gate.disabled);
    setRegexText((gate.any_command_regex ?? []).join("\n"));
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
      const regexes = regexText
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      await apiSend(`/v1/policy/gates/${encodeURIComponent(gate.id)}`, "PATCH", {
        disabled,
        mode,
        any_command_regex: regexes,
      });
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

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
            <div className="text-xs font-mono text-neutral-100">{gate.tool || "—"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted mb-1">tool_prefix</div>
            <div className="text-xs font-mono text-neutral-100">{gate.tool_prefix || "—"}</div>
          </div>
        </div>

        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted mb-1">evaluators</div>
          <div className="text-xs font-mono text-neutral-100">
            {gate.evaluators.length > 0 ? gate.evaluators.join(", ") : "—"}
          </div>
        </div>

        <div>
          <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
            any_command_regex (one per line)
          </label>
          <textarea
            className="oal-input w-full font-mono min-h-[96px]"
            value={regexText}
            onChange={(e) => setRegexText(e.target.value)}
          />
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
          Tool, tool_prefix, evaluators are not yet editable inline — delete + re-add to change
          those.
        </div>
      </div>
    </aside>
  );
}
