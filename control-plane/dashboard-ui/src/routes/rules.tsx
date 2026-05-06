import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { AddRuleModal } from "@/components/AddRuleModal";
import { ModeToggle } from "@/components/ModeToggle";
import { RuleEditDrawer } from "@/components/RuleEditDrawer";
import { useModeInfo, usePolicyView } from "@/hooks/usePoll";
import { apiSend } from "@/lib/api";
import type { GateView } from "@/lib/types";

function RulesTab() {
  const { policy, error, refresh } = usePolicyView(true);
  const { mode, setMode } = useModeInfo();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const selected: GateView | null =
    policy?.gates.find((g) => g.id === selectedId) ?? null;

  const onToggle = async (gate: GateView, enabled: boolean) => {
    setActionError(null);
    try {
      await apiSend(`/v1/policy/gates/${encodeURIComponent(gate.id)}`, "PATCH", {
        disabled: !enabled,
      });
      await refresh();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  };

  const onDelete = async (gate: GateView) => {
    if (!confirm(`Delete rule ${gate.id}?`)) return;
    setActionError(null);
    try {
      await apiSend(`/v1/policy/gates/${encodeURIComponent(gate.id)}`, "DELETE");
      if (selectedId === gate.id) setSelectedId(null);
      await refresh();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="space-y-4">
      <section className="oal-panel">
        <div className="text-[11px] uppercase tracking-wider text-muted mb-2">Daemon mode</div>
        <ModeToggle mode={mode} setMode={setMode} />
        <div className="text-xs text-muted mt-3 space-y-0.5">
          <div>
            <span className="text-monitor font-semibold">Monitor</span> — record + allow.
          </div>
          <div>
            <span className="text-deny font-semibold">Firewall</span> — enforce deny.
          </div>
        </div>
      </section>

      <section className="grid grid-cols-[1fr_360px] gap-4 items-start">
        <div className="oal-panel">
          <div className="flex items-center gap-3 mb-3">
            <div className="text-[11px] uppercase tracking-wider text-muted">Policy gates</div>
            <button
              type="button"
              className="oal-btn ml-auto"
              onClick={() => setShowAdd(true)}
            >
              + Add rule
            </button>
          </div>

          <div className="border border-monitor/40 bg-monitor/10 text-monitor text-xs px-3 py-2 rounded mb-3">
            Policy changes apply to new sessions. Existing sessions keep the policy they started
            with until reload.
          </div>

          {error && <div className="text-xs text-deny mb-2">{error}</div>}
          {actionError && <div className="text-xs text-deny mb-2">{actionError}</div>}

          <div className="overflow-x-auto">
            <table className="oal-table">
              <thead>
                <tr>
                  <th style={{ width: 48 }}>on</th>
                  <th>id</th>
                  <th>mode</th>
                  <th>source</th>
                  <th>tool</th>
                  <th>match</th>
                  <th style={{ width: 96 }}>actions</th>
                </tr>
              </thead>
              <tbody>
                {policy?.gates && policy.gates.length > 0 ? (
                  policy.gates.map((g) => (
                    <tr
                      key={g.id}
                      onClick={() => setSelectedId(g.id)}
                      className={`cursor-pointer ${
                        g.id === selectedId ? "bg-chip" : "hover:bg-chip/50"
                      }`}
                    >
                      <td onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={!g.disabled}
                          onChange={(e) => onToggle(g, e.target.checked)}
                        />
                      </td>
                      <td className="font-mono">{g.id}</td>
                      <td>
                        <span className="oal-chip">{g.mode || "inherit"}</span>
                      </td>
                      <td className="font-mono text-muted text-[11px]">{g.source || "daemon"}</td>
                      <td className="font-mono">{g.tool || g.tool_prefix || "—"}</td>
                      <td className="font-mono text-muted text-[11px]">
                        {g.any_command_regex && g.any_command_regex.length > 0
                          ? g.any_command_regex.slice(0, 2).join(" | ") +
                            (g.any_command_regex.length > 2
                              ? ` +${g.any_command_regex.length - 2}`
                              : "")
                          : Array.isArray(g.evaluators) && g.evaluators.length > 0
                            ? g.evaluators.join(", ")
                            : "—"}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          className="oal-btn-link text-deny"
                          onClick={() => onDelete(g)}
                        >
                          delete
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="text-center text-muted py-4">
                      no rules
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <RuleEditDrawer
          gate={selected}
          onSaved={async () => {
            setActionError(null);
            try {
              await refresh();
            } catch (e) {
              setActionError(e instanceof Error ? e.message : String(e));
            }
          }}
          onClose={() => setSelectedId(null)}
        />
      </section>

      {showAdd && (
        <AddRuleModal
          onClose={() => setShowAdd(false)}
          onCreated={async (id) => {
            setShowAdd(false);
            setSelectedId(id);
            setActionError(null);
            try {
              await refresh();
            } catch (e) {
              setActionError(e instanceof Error ? e.message : String(e));
            }
          }}
        />
      )}
    </div>
  );
}

export const Route = createFileRoute("/rules")({
  component: RulesTab,
});
