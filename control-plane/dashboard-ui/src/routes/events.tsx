import type React from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { AddRuleModal } from "@/components/AddRuleModal";
import { useRootInfo } from "@/hooks/usePoll";
import { useSSELedger } from "@/hooks/useSSE";
import { apiJSON, apiSend } from "@/lib/api";
import type {
  FalsePositiveApplyResult,
  FalsePositiveCase,
  FalsePositiveValidation,
  LedgerEntry,
} from "@/lib/types";
import { INTERNAL_SOURCES } from "@/lib/filters";
import { fullLocal, shortTime } from "@/lib/time";
import { shortHash } from "@/lib/filters";
import { rulePresetFromLedgerEntry } from "@/lib/eventRulePreset";
import {
  isOutcomeEntry,
  outcomeByToolUseId,
  subjectFromLedgerEntry,
} from "@/lib/ledgerEntryDisplay";
import type { AddRuleInitialPreset } from "@/lib/rulePresetTypes";

// verdictDisplay maps a ledger row to a (label, color-class) pair.
//
// Categories:
//   - Pre-tool gate verdicts: allow (green) / deny (red) / alert (amber,
//     when monitor mode suppressed a deny — IDS, not IPS).
//   - Post-tool outcomes: complete = "ran" / failure = "tool errored".
//     Both are informational — they describe the tool's own exit code,
//     not an agentlock decision. They get a neutral chip so they don't
//     read as security failures next to a real deny.
function verdictDisplay(
  verdict: string | undefined,
  monitorMatch: boolean | undefined,
): { label: string; cls: string } {
  if (verdict === "deny" && monitorMatch) {
    return { label: "alert", cls: "bg-monitor/20 text-monitor" };
  }
  if (verdict === "allow") return { label: "allow", cls: "bg-allow/20 text-allow" };
  if (verdict === "deny") return { label: "deny", cls: "bg-deny/20 text-deny" };
  if (verdict === "monitor") return { label: "monitor", cls: "bg-monitor/20 text-monitor" };
  if (verdict === "complete") return { label: "ran", cls: "bg-chip text-muted" };
  if (verdict === "failure") return { label: "tool errored", cls: "bg-chip text-muted" };
  return { label: verdict ?? "—", cls: "bg-chip text-muted" };
}

function statusClass(status: string): string {
  if (status === "connected") return "bg-allow/20 text-allow";
  if (status === "reconnecting") return "bg-monitor/20 text-monitor";
  return "bg-chip text-muted";
}

function EventsTab() {
  const { entries, status } = useSSELedger(5000);
  const { root, rootError } = useRootInfo();

  const [sourceFilter, setSourceFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");
  const [ruleFilter, setRuleFilter] = useState("");
  const [showInternal, setShowInternal] = useState(false);
  const [showOutcomes, setShowOutcomes] = useState(false);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    preset: AddRuleInitialPreset;
  } | null>(null);
  const [addRulePreset, setAddRulePreset] = useState<AddRuleInitialPreset | null>(null);

  // Reset to page 0 when filter inputs or page size change so the user
  // never lands on an empty page after narrowing the result set.
  useEffect(() => {
    setPage(0);
  }, [sourceFilter, verdictFilter, ruleFilter, showInternal, showOutcomes, pageSize]);

  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("keydown", onKey);
    };
  }, [contextMenu]);

  const sources = useMemo(() => {
    const set = new Set<string>();
    entries.forEach((e) => set.add(e.source));
    return Array.from(set).sort();
  }, [entries]);

  const verdicts = useMemo(() => {
    const set = new Set<string>();
    entries.forEach((e) => {
      if (e.verdict) set.add(e.verdict);
    });
    return Array.from(set).sort();
  }, [entries]);

  const filtered = useMemo(() => {
    const rule = ruleFilter.trim().toLowerCase();
    return entries
      .filter((e) => {
        if (!showInternal && INTERNAL_SOURCES.has(e.source)) return false;
        if (isOutcomeEntry(e)) return false;
        if (sourceFilter && e.source !== sourceFilter) return false;
        if (verdictFilter && e.verdict !== verdictFilter) return false;
        if (rule && !(e.rule_id ?? "").toLowerCase().includes(rule)) return false;
        return true;
      })
      .slice()
      .sort((a, b) => b.seq - a.seq);
  }, [entries, sourceFilter, verdictFilter, ruleFilter, showInternal]);

  const outcomes = useMemo(() => outcomeByToolUseId(entries), [entries]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const pageStart = safePage * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, filtered.length);
  const paged = useMemo(
    () => filtered.slice(pageStart, pageEnd),
    [filtered, pageStart, pageEnd],
  );

  const onRowContextMenu = (ev: React.MouseEvent, entry: LedgerEntry) => {
    const preset = rulePresetFromLedgerEntry(entry);
    if (!preset) return;
    ev.preventDefault();
    setContextMenu({
      x: Math.min(ev.clientX, window.innerWidth - 220),
      y: Math.min(ev.clientY, window.innerHeight - 64),
      preset,
    });
  };

  return (
    <div className="space-y-4">
      <section className="oal-panel">
        <div className="flex items-start gap-6 flex-wrap">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted">Merkle root</div>
            <div className="text-xs font-mono text-neutral-100 break-all">
              {root?.root ? shortHash(root.root, 32) : "—"}
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted">seq</div>
            <div className="text-xs font-mono">{root?.seq ?? "—"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted">count</div>
            <div className="text-xs font-mono">{root?.count ?? "—"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted">computed</div>
            <div className="text-xs font-mono" title={fullLocal(root?.computed_at)}>
              {shortTime(root?.computed_at)}
            </div>
          </div>
          <div className="ml-auto">
            <span
              className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${statusClass(status)}`}
            >
              sse: {status}
            </span>
          </div>
        </div>
        {rootError && <div className="text-xs text-deny mt-2">{rootError}</div>}
      </section>

      <section className="oal-panel">
        <div className="flex items-center gap-3 flex-wrap mb-3">
          <label className="flex items-center gap-1 text-[11px] text-muted">
            source
            <select
              className="oal-input"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <option value="">all</option>
              {sources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1 text-[11px] text-muted">
            verdict
            <select
              className="oal-input"
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
            >
              <option value="">all</option>
              {verdicts.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1 text-[11px] text-muted">
            rule contains
            <input
              className="oal-input"
              value={ruleFilter}
              onChange={(e) => setRuleFilter(e.target.value)}
              placeholder="pkg-install"
            />
          </label>
          <label className="flex items-center gap-2 text-[11px] text-muted ml-auto">
            <input
              type="checkbox"
              checked={showOutcomes}
              onChange={(e) => setShowOutcomes(e.target.checked)}
            />
            show tool outcomes
          </label>
          <label className="flex items-center gap-2 text-[11px] text-muted">
            <input
              type="checkbox"
              checked={showInternal}
              onChange={(e) => setShowInternal(e.target.checked)}
            />
            show internal
          </label>
        </div>

        <div className="overflow-x-auto">
          <table className="oal-table">
            <thead>
              <tr>
                <th>seq</th>
                <th>time</th>
                <th>source</th>
                <th>rule</th>
                <th>verdict</th>
                <th>signer</th>
                <th>tool_use_id</th>
                <th>leaf</th>
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center text-muted py-4">
                    no events
                  </td>
                </tr>
              ) : (
                paged.map((e) => {
                  const outcome = showOutcomes ? outcomes.get(e.tool_use_id) : undefined;
                  return (
                    <EventRows
                      key={`${e.seq}-${e.leaf_hash}`}
                      entry={e}
                      outcome={outcome}
                      onSelect={setSelectedSeq}
                      onContextMenu={onRowContextMenu}
                    />
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center gap-3 flex-wrap mt-3 text-[11px] text-muted">
          <div>
            {filtered.length === 0
              ? "0 events"
              : `showing ${pageStart + 1}-${pageEnd} of ${filtered.length}`}
          </div>
          <label className="flex items-center gap-1 ml-auto">
            page size
            <select
              className="oal-input"
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </label>
          <button
            type="button"
            className="oal-btn-link disabled:opacity-40 disabled:cursor-not-allowed"
            disabled={safePage <= 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            prev
          </button>
          <span className="font-mono">
            {safePage + 1} / {pageCount}
          </span>
          <button
            type="button"
            className="oal-btn-link disabled:opacity-40 disabled:cursor-not-allowed"
            disabled={safePage >= pageCount - 1}
            onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
          >
            next
          </button>
        </div>
      </section>

      {selectedSeq !== null && (
        <EventDetail
          entry={entries.find((e) => e.seq === selectedSeq) ?? null}
          onClose={() => setSelectedSeq(null)}
        />
      )}

      {contextMenu && (
        <div
          className="fixed z-50 min-w-[200px] rounded-md border border-border bg-panel py-1 shadow-lg"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
          role="menu"
        >
          <button
            type="button"
            className="block w-full px-3 py-2 text-left text-xs hover:bg-chip focus:bg-chip focus:outline-none"
            onClick={() => {
              setAddRulePreset(contextMenu.preset);
              setContextMenu(null);
            }}
            role="menuitem"
          >
            Block this next time
          </button>
        </div>
      )}

      {addRulePreset && (
        <AddRuleModal
          initialPreset={addRulePreset}
          onClose={() => setAddRulePreset(null)}
          onCreated={() => setAddRulePreset(null)}
        />
      )}
    </div>
  );
}

function EventRows({
  entry,
  outcome,
  onSelect,
  onContextMenu,
}: {
  entry: LedgerEntry;
  outcome?: LedgerEntry;
  onSelect: (seq: number) => void;
  onContextMenu: (ev: React.MouseEvent, entry: LedgerEntry) => void;
}) {
  const v = verdictDisplay(entry.verdict, entry.monitor_match);
  const tip = entry.monitor_match
    ? `monitor mode: rule ${entry.rule_id ?? ""} would have denied`
    : undefined;
  const outcomeVerdict = outcome ? verdictDisplay(outcome.verdict, outcome.monitor_match) : null;
  return (
    <>
      <tr
        onClick={() => onSelect(entry.seq)}
        onContextMenu={(ev) => onContextMenu(ev, entry)}
        className="cursor-pointer hover:bg-chip"
      >
        <td className="font-mono">{entry.seq}</td>
        <td className="font-mono" title={fullLocal(entry.ts)}>
          {shortTime(entry.ts)}
        </td>
        <td>
          <span className="oal-chip">{entry.source}</span>
        </td>
        <td className="font-mono">{entry.rule_id || "—"}</td>
        <td>
          {entry.verdict ? (
            <span
              className={`inline-block px-1.5 py-0.5 rounded text-[11px] ${v.cls}`}
              title={tip}
            >
              {v.label}
            </span>
          ) : (
            <span className="text-muted">—</span>
          )}
        </td>
        <td className="font-mono">{entry.signer}</td>
        <td className="font-mono text-muted">{shortHash(entry.tool_use_id, 16)}</td>
        <td className="font-mono text-muted" title={entry.leaf_hash}>
          {shortHash(entry.leaf_hash, 12)}
        </td>
      </tr>
      {outcome && outcomeVerdict && (
        <tr
          onClick={() => onSelect(outcome.seq)}
          className="cursor-pointer bg-chip/30 hover:bg-chip text-muted"
        >
          <td className="font-mono pl-6">↳ {outcome.seq}</td>
          <td className="font-mono" title={fullLocal(outcome.ts)}>
            {shortTime(outcome.ts)}
          </td>
          <td>
            <span className="oal-chip">{outcome.source}</span>
          </td>
          <td className="font-mono text-muted">tool outcome</td>
          <td>
            <span
              className={`inline-block px-1.5 py-0.5 rounded text-[11px] ${outcomeVerdict.cls}`}
            >
              {outcomeVerdict.label}
            </span>
          </td>
          <td className="font-mono">{outcome.signer}</td>
          <td className="font-mono text-muted">{shortHash(outcome.tool_use_id, 16)}</td>
          <td className="font-mono text-muted" title={outcome.leaf_hash}>
            {shortHash(outcome.leaf_hash, 12)}
          </td>
        </tr>
      )}
    </>
  );
}

// EventDetail renders every field on a ledger entry — verdict, monitor
// match, payload + leaf hashes, signer — so a user inspecting "why
// did this row show up" can see the full chain context without diving
// into ledger.jsonl by hand. Closes on backdrop click or the X button.
function EventDetail({
  entry,
  onClose,
}: {
  entry: LedgerEntry | null;
  onClose: () => void;
}) {
  const [fpCase, setFpCase] = useState<FalsePositiveCase | null>(null);
  const [replacementYAML, setReplacementYAML] = useState("");
  const [fpValidation, setFpValidation] = useState<FalsePositiveValidation | null>(
    null,
  );
  const [fpApply, setFpApply] = useState<FalsePositiveApplyResult | null>(null);
  const [fpError, setFpError] = useState<string | null>(null);
  const [fpBusy, setFpBusy] = useState(false);
  // Esc-to-close + initial focus on the close button. Focus trap is left
  // out for now — the dialog has a single interactive element so Tab
  // would just cycle there anyway.
  const closeBtnRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    closeBtnRef.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!entry) {
    return (
      <div
        className="fixed inset-0 bg-black/60 flex items-center justify-center z-40"
        onClick={onClose}
        role="dialog"
        aria-modal="true"
      >
        <div className="bg-panel border border-border rounded p-4 text-sm text-muted">
          entry not loaded — try again
        </div>
      </div>
    );
  }
  const v = verdictDisplay(entry.verdict, entry.monitor_match);
  const subject = subjectFromLedgerEntry(entry);
  const canReportFalsePositive =
    !!entry.rule_id &&
    entry.rule_id !== "default" &&
    !isOutcomeEntry(entry) &&
    (entry.verdict === "deny" || !!entry.monitor_match);

  async function loadFalsePositiveCase() {
    if (!entry) return;
    setFpBusy(true);
    setFpError(null);
    setFpApply(null);
    setFpValidation(null);
    try {
      const c = await apiJSON<FalsePositiveCase>(
        `/v1/false-positives/cases/${entry.seq}`,
      );
      setFpCase(c);
      setReplacementYAML(defaultReplacementYAML(c));
    } catch (err) {
      setFpError((err as Error).message);
    } finally {
      setFpBusy(false);
    }
  }

  async function validateFalsePositive() {
    if (!fpCase) return;
    setFpBusy(true);
    setFpError(null);
    setFpApply(null);
    try {
      const validation = await apiSend<FalsePositiveValidation>(
        "/v1/false-positives/validate",
        "POST",
        { case: fpCase, replacement_yaml: replacementYAML },
      );
      setFpValidation(validation);
    } catch (err) {
      setFpError((err as Error).message);
    } finally {
      setFpBusy(false);
    }
  }

  async function applyFalsePositive() {
    if (!fpCase) return;
    setFpBusy(true);
    setFpError(null);
    try {
      const applied = await apiSend<FalsePositiveApplyResult>(
        "/v1/false-positives/apply",
        "POST",
        { case: fpCase, replacement_yaml: replacementYAML },
      );
      setFpApply(applied);
      setFpValidation({ ok: true, replacement_id: applied.replacement_id });
    } catch (err) {
      setFpError((err as Error).message);
    } finally {
      setFpBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-40"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={`ledger entry ${entry.seq}`}
    >
      <div
        className="bg-panel border border-border rounded-md w-[640px] max-h-[85vh] overflow-y-auto p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between mb-3">
          <div className="text-sm font-semibold text-neutral-100">
            ledger entry #{entry.seq}
          </div>
          <button
            ref={closeBtnRef}
            type="button"
            className="oal-btn-link"
            onClick={onClose}
          >
            close
          </button>
        </div>
        <DetailRow label="time" value={fullLocal(entry.ts)} mono />
        <DetailRow label="source" value={entry.source} />
        {subject && (
          <DetailRow
            label={subject.label}
            value={<span className="whitespace-pre-wrap break-words">{subject.value}</span>}
            mono
          />
        )}
        <DetailRow label="rule" value={entry.rule_id ?? "—"} mono />
        <DetailRow
          label="verdict"
          value={
            <span
              className={`inline-block px-1.5 py-0.5 rounded text-[11px] ${v.cls}`}
              title={
                entry.monitor_match
                  ? `monitor mode: rule ${entry.rule_id ?? ""} would have denied`
                  : undefined
              }
            >
              {v.label}
            </span>
          }
        />
        {entry.monitor_match && (
          <DetailRow
            label="monitor"
            value="suppressed deny — runtime allowed; ledger keeps original verdict"
          />
        )}
        {entry.policy_trace && entry.policy_trace.length > 0 && (
          <DetailRow
            label="policy"
            value={entry.policy_trace
              .map((t) => {
                const priority =
                  t.precedence === "priority" ? ` priority=${t.priority ?? 0}` : "";
                return `${t.layer || t.source || "policy"}:${t.rule_id}=${t.verdict}${priority}`;
              })
              .join(" → ")}
            mono
            wrap
          />
        )}
        <DetailRow label="signer" value={entry.signer || "—"} mono />
        <DetailRow label="tool_use_id" value={entry.tool_use_id || "—"} mono />
        <DetailRow label="payload_hash" value={entry.payload_hash} mono wrap />
        <DetailRow label="leaf_hash" value={entry.leaf_hash} mono wrap />
        <DetailRow label="prev_leaf" value={entry.prev_leaf} mono wrap />
        {entry.sig && entry.sig.length > 0 && (
          <DetailRow label="sig" value={entry.sig} mono wrap />
        )}
        {canReportFalsePositive && (
          <div className="mt-4 border-t border-border pt-4">
            <button
              type="button"
              className="oal-btn-link"
              onClick={loadFalsePositiveCase}
              disabled={fpBusy}
            >
              {fpCase ? "refresh false-positive case" : "report false positive"}
            </button>
          </div>
        )}
        {fpCase && (
          <div className="mt-4 rounded border border-border bg-black/20 p-3">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">
              False positive case
            </div>
            <DetailRow
              label="matched"
              value={`${fpCase.matched_gate.id} (${fpCase.matched_gate.source})`}
              mono
              wrap
            />
            {Object.entries(fpCase.input).map(([k, val]) => (
              <DetailRow key={k} label={k} value={val} mono wrap />
            ))}
            <label className="mt-3 block text-[10px] uppercase tracking-wider text-muted">
              replacement rule
            </label>
            <textarea
              className="mt-1 h-44 w-full resize-y rounded border border-border bg-bg p-2 font-mono text-xs text-neutral-100"
              value={replacementYAML}
              onChange={(e) => {
                setReplacementYAML(e.target.value);
                setFpValidation(null);
                setFpApply(null);
              }}
              spellCheck={false}
            />
            <div className="mt-3 flex gap-2">
              <button
                type="button"
                className="oal-btn-link"
                onClick={validateFalsePositive}
                disabled={fpBusy}
              >
                validate
              </button>
              <button
                type="button"
                className="oal-btn-link"
                onClick={applyFalsePositive}
                disabled={fpBusy || fpValidation?.ok !== true}
              >
                apply replacement
              </button>
            </div>
            {fpValidation && (
              <div
                className={`mt-2 text-xs ${
                  fpValidation.ok ? "text-allow" : "text-deny"
                }`}
              >
                {fpValidation.ok
                  ? `valid; original event verdict: ${fpValidation.replacement_verdict ?? "allow"}`
                  : (fpValidation.errors ?? ["validation failed"]).join("; ")}
              </div>
            )}
            {fpApply && (
              <div className="mt-2 text-xs text-allow">
                applied {fpApply.replacement_id}; reload sessions to pick up policy{" "}
                {shortHash(fpApply.hash)}
              </div>
            )}
            {fpError && <div className="mt-2 text-xs text-deny">{fpError}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

function defaultReplacementYAML(c: FalsePositiveCase): string {
  const tool = c.event.tool ? `  tool: ${JSON.stringify(c.event.tool)}\n` : "";
  return `id: ${c.event.rule_id}.replacement
match:
${tool}  any_command_regex:
    - '(?!)'
evaluate:
  - kind: always
    action: deny
`;
}

function DetailRow({
  label,
  value,
  mono,
  wrap,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  wrap?: boolean;
}) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3 py-1.5 border-b border-border/50 last:border-0 text-xs">
      <div className="text-muted uppercase tracking-wider text-[10px] pt-1">
        {label}
      </div>
      <div className={`${mono ? "font-mono" : ""} ${wrap ? "break-all" : ""}`}>
        {value}
      </div>
    </div>
  );
}

export const Route = createFileRoute("/events")({
  component: EventsTab,
});
