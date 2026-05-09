// OpenAgentLock dashboard TUI. Keyboard-driven viewer + control surface
// over the same JSON endpoints the web dashboard talks to. Aims to match
// the web dashboard feature-for-feature so users can drive the daemon
// from a terminal alone.
//
// Tabs:  Stats | Events | Sessions | Gates | Mode
//   1/2/3 (on Stats)  switch insight window (1h / 24h / 7d)
//   h/l or ←/→        switch tab
//   j/k or ↑/↓        move cursor / scroll within the focused tab
//   m                 flip daemon-wide mode (firewall ↔ monitor)
//   r                 force-refresh the focused tab
//   q or esc          quit (also closes any open modal first)
//
// Per-tab keys (footer shows the active set):
//   Events:  enter open detail   f filter   c clear filters   i internal   o outcomes   H hashes
//   Gates:   enter detail   a add (editor)   e edit (editor)   space toggle disabled   M cycle mode   x x delete
//   Sessions: i toggle internal harnesses
//
// The daemon base URL comes from the ApiClient passed in (so tests can
// point at a Bun.serve() mock and the real CLI points at 127.0.0.1:7878).

import { createCliRenderer, type KeyEvent } from "@opentui/core";
import { createRoot, flushSync, useRenderer } from "@opentui/react";
import { useEffect, useRef, useState } from "react";
import type {
  ApiClient,
  FalsePositiveCaseResponse,
  GuardrailCatalogResponse,
  GuardrailEnabledEntry,
  GuardrailEnabledResponse,
  GuardrailProvidersResponse,
  InsightWindow,
  LedgerInsightsResponse,
  LedgerRootResponse,
  ModeResponse,
  PolicyGateView,
  PolicyMatchView,
  PolicyViewResponse,
  SessionsListResponse,
  SessionSummary,
} from "../util/api.ts";
import { editYAMLInEditor } from "../util/editor.ts";

// ---------- shared types ---------------------------------------------------

interface LedgerEntry {
  seq: number;
  ts: string;
  source: string;
  tool_use_id: string;
  tool?: string;
  signer: string;
  input?: Record<string, unknown>;
  tool_input?: Record<string, unknown>;
  rule_id?: string;
  verdict?: string;
  monitor_match?: boolean;
  payload_hash?: string;
  sig?: string;
  leaf_hash?: string;
  prev_leaf?: string;
}

type TabName = "stats" | "events" | "guardrails" | "sessions" | "gates" | "mode";

const TABS: { name: string; description: string; value: TabName }[] = [
  { name: "Stats", description: "Operational insights", value: "stats" },
  { name: "Events", description: "Live ledger tail", value: "events" },
  { name: "Guardrails", description: "External guardrails", value: "guardrails" },
  { name: "Sessions", description: "Who's connected", value: "sessions" },
  { name: "Gates", description: "Loaded policy gates", value: "gates" },
  { name: "Mode", description: "Firewall / monitor", value: "mode" },
];

const VISIBLE_ROWS = 16;

interface Filters {
  source: string;
  verdict: string;
  rule: string;
  internal: boolean;
  outcomes: boolean;
}
const EMPTY_FILTERS: Filters = {
  source: "",
  verdict: "",
  rule: "",
  internal: false,
  outcomes: false,
};
type FilterField = "source" | "verdict" | "rule";
const FILTER_FIELDS: FilterField[] = ["source", "verdict", "rule"];

const NEW_GATE_TEMPLATE = `# Define a new policy gate. The yaml below is fed to
# POST /v1/policy/gates/yaml — same schema as policies/default.yaml.
# Save and quit your editor to apply; close without saving to abort.
id: my-rule
match:
  tool: Bash
  any_command_regex:
    - 'curl\\s+-fsSL\\b'
evaluate:
  - kind: always
    action: deny
`;

interface DashboardProps {
  api: ApiClient;
  onQuit: () => void;
}

function useInterval(cb: () => void, ms: number): void {
  const cbRef = useRef(cb);
  useEffect(() => {
    cbRef.current = cb;
  }, [cb]);
  useEffect(() => {
    cbRef.current();
    const id = setInterval(() => cbRef.current(), ms);
    return () => clearInterval(id);
  }, [ms]);
}

// ---------- app root -------------------------------------------------------

function Dashboard({ api, onQuit }: DashboardProps): React.ReactNode {
  const [tab, setTab] = useState<TabName>("stats");
  const [cursor, setCursor] = useState<Record<TabName, number>>({
    stats: 0,
    events: 0,
    guardrails: 0,
    sessions: 0,
    gates: 0,
    mode: 0,
  });
  const [scroll, setScroll] = useState<Record<TabName, number>>({
    stats: 0,
    events: 0,
    guardrails: 0,
    sessions: 0,
    gates: 0,
    mode: 0,
  });
  const [daemonOk, setDaemonOk] = useState<boolean | null>(null);
  const [mode, setMode] = useState<ModeResponse | null>(null);
  const [sessions, setSessions] = useState<SessionsListResponse | null>(null);
  const [policy, setPolicy] = useState<PolicyViewResponse | null>(null);
  const [guardrailProviders, setGuardrailProviders] =
    useState<GuardrailProvidersResponse | null>(null);
  const [guardrailCatalog, setGuardrailCatalog] =
    useState<GuardrailCatalogResponse | null>(null);
  const [guardrailEnabled, setGuardrailEnabled] =
    useState<GuardrailEnabledResponse | null>(null);
  const [events, setEvents] = useState<LedgerEntry[]>([]);
  const [insights, setInsights] = useState<LedgerInsightsResponse | null>(null);
  const [statsWindow, setStatsWindow] = useState<InsightWindow>("24h");
  const [ledgerRoot, setLedgerRoot] = useState<LedgerRootResponse | null>(null);
  const [sseStatus, setSseStatus] = useState<"connecting" | "open" | "closed">(
    "connecting",
  );
  const [toast, setToast] = useState<string>("");

  // Events tab state.
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [filterField, setFilterField] = useState<FilterField | null>(null);
  const [filterBuffer, setFilterBuffer] = useState<string>("");
  const [detailSeq, setDetailSeq] = useState<number | null>(null);
  const [expandHashes, setExpandHashes] = useState<boolean>(false);

  // Sessions tab state.
  const [showInternal, setShowInternal] = useState<boolean>(false);

  // Gates tab state — two-key delete confirmation. First `x` sets a
  // window during which a second `x` commits; expires on its own.
  const [pendingDelete, setPendingDelete] = useState<{
    gateId: string;
    expiresAt: number;
  } | null>(null);
  const [gateDetailId, setGateDetailId] = useState<string | null>(null);
  const [gateDetailScroll, setGateDetailScroll] = useState<number>(0);

  // Editor flow state — when true, the renderer is suspended and
  // keypresses skip the TUI handler (the editor owns the TTY).
  const editorActiveRef = useRef<boolean>(false);

  // Polling: health, mode, sessions, policy, ledger root.
  useInterval(() => {
    api.health().then(() => setDaemonOk(true)).catch(() => setDaemonOk(false));
    api.getMode().then(setMode).catch(() => {});
    api.listSessions().then(setSessions).catch(() => {});
    api.policyView().then(setPolicy).catch(() => {});
    api.guardrailProviders().then(setGuardrailProviders).catch(() => {});
    api.guardrailCatalog().then(setGuardrailCatalog).catch(() => {});
    api.guardrailEnabled().then(setGuardrailEnabled).catch(() => {});
    api.ledgerRoot().then(setLedgerRoot).catch(() => {});
  }, 2000);

  // Insights polling — separate cadence so a stuck ledger doesn't block
  // mode/policy refreshes.
  useInterval(() => {
    api.ledgerInsights(statsWindow).then(setInsights).catch(() => {});
  }, 5000);
  // Re-fetch immediately when the user changes window so the panel
  // doesn't show stale data for up to 5s.
  useEffect(() => {
    api.ledgerInsights(statsWindow).then(setInsights).catch(() => {});
  }, [api, statsWindow]);

  // SSE ledger tail. Bun has no global EventSource, so the API client
  // tails the stream over fetch+ReadableStream and we just plumb the
  // entries / status into local state.
  useEffect(() => {
    return api.tailLedger({
      onStatus: setSseStatus,
      onEntry: (entry) =>
        setEvents((prev) => [entry as LedgerEntry, ...prev].slice(0, 500)),
    });
  }, [api]);

  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function flashToast(msg: string): void {
    setToast(msg);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(""), 2500);
  }
  useEffect(() => {
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current);
    };
  }, []);

  // Refs so the keypress handler always sees fresh state without
  // re-installing on every render.
  const tabRef = useRef(tab);
  tabRef.current = tab;
  const modeRef = useRef(mode);
  modeRef.current = mode;
  const policyRef = useRef(policy);
  policyRef.current = policy;
  const eventsRef = useRef(events);
  eventsRef.current = events;
  const cursorRef = useRef(cursor);
  cursorRef.current = cursor;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const filterFieldRef = useRef(filterField);
  filterFieldRef.current = filterField;
  const filterBufferRef = useRef(filterBuffer);
  filterBufferRef.current = filterBuffer;
  const detailSeqRef = useRef(detailSeq);
  detailSeqRef.current = detailSeq;
  const gateDetailIdRef = useRef(gateDetailId);
  gateDetailIdRef.current = gateDetailId;
  const gateDetailScrollRef = useRef(gateDetailScroll);
  gateDetailScrollRef.current = gateDetailScroll;
  const showInternalRef = useRef(showInternal);
  showInternalRef.current = showInternal;
  const pendingDeleteRef = useRef(pendingDelete);
  pendingDeleteRef.current = pendingDelete;
  const statsWindowRef = useRef(statsWindow);
  statsWindowRef.current = statsWindow;
  const guardrailCatalogRef = useRef(guardrailCatalog);
  guardrailCatalogRef.current = guardrailCatalog;
  const guardrailEnabledRef = useRef(guardrailEnabled);
  guardrailEnabledRef.current = guardrailEnabled;

  // Filtered/visible derivations used by the keyboard handler when
  // computing what's "under the cursor."
  function filteredEvents(): LedgerEntry[] {
    const f = filtersRef.current;
    let arr = eventsRef.current;
    arr = arr.filter((e) => !isOutcomeEntry(e));
    if (f.source) arr = arr.filter((e) => e.source === f.source);
    if (f.verdict)
      arr = arr.filter((e) => (e.verdict || "") === f.verdict);
    if (f.rule) arr = arr.filter((e) => (e.rule_id || "").includes(f.rule));
    if (!f.internal) {
      // "internal" off = operator-facing policy decisions only. Outcome
      // receipts are handled separately under the matching tool row.
      arr = arr.filter(
        (e) =>
          !INTERNAL_SOURCES.has(e.source || "") &&
          (Boolean(e.rule_id) || Boolean(e.monitor_match)),
      );
    }
    return arr;
  }

  function visibleSessions(): SessionSummary[] {
    if (!sessions) return [];
    if (showInternalRef.current) return sessions.sessions;
    return sessions.sessions.filter(
      (s) => !INTERNAL_HARNESSES.has(s.harness || ""),
    );
  }

  function visibleGuardrails() {
    return guardrailCatalogRef.current?.entries ?? [];
  }

  function moveCursor(delta: number): void {
    const t = tabRef.current;
    let max = 0;
    if (t === "events") max = filteredEvents().length;
    else if (t === "guardrails") max = visibleGuardrails().length;
    else if (t === "sessions") max = visibleSessions().length;
    else if (t === "gates") max = policyRef.current?.gates.length ?? 0;
    if (max === 0) return;
    const cur = cursorRef.current[t] ?? 0;
    const next = Math.max(0, Math.min(max - 1, cur + delta));
    flushSync(() => {
      setCursor((s) => ({ ...s, [t]: next }));
      setScroll((s) => {
        const off = s[t];
        if (next < off) return { ...s, [t]: next };
        if (next >= off + VISIBLE_ROWS)
          return { ...s, [t]: next - VISIBLE_ROWS + 1 };
        return s;
      });
    });
  }

  // Spawn $EDITOR on a YAML buffer. Suspends the renderer so the
  // editor owns the TTY, then resumes once the user exits.
  async function runEditor(seed: string, hint: string): Promise<string | null> {
    editorActiveRef.current = true;
    let result: string | null = null;
    try {
      try {
        renderer.suspend();
      } catch {
        // older opentui may not expose suspend — fall through; the
        // editor will share the TTY with the renderer for that brief
        // window. Bug, not a crash.
      }
      try {
        const r = await editYAMLInEditor(seed, hint);
        if (!r.unchanged && r.content.trim().length > 0) result = r.content;
      } catch (err) {
        flashToast(
          `editor failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    } finally {
      try {
        renderer.resume();
      } catch {
        // best-effort
      }
      editorActiveRef.current = false;
    }
    return result;
  }

  function refreshPolicy(): void {
    api.policyView()
      .then((r) => flushSync(() => setPolicy(r)))
      .catch(() => {});
  }

  function refreshGuardrails(): void {
    api.guardrailProviders()
      .then((r) => flushSync(() => setGuardrailProviders(r)))
      .catch(() => {});
    api.guardrailCatalog()
      .then((r) => flushSync(() => setGuardrailCatalog(r)))
      .catch(() => {});
    api.guardrailEnabled()
      .then((r) => flushSync(() => setGuardrailEnabled(r)))
      .catch(() => {});
  }

  function isGuardrailEnabled(entry: { provider_id: string; entry_id: string }): boolean {
    return (guardrailEnabledRef.current?.entries ?? []).some(
      (item) =>
        item.provider_id === entry.provider_id && item.entry_id === entry.entry_id,
    );
  }

  function toggleGuardrail(entry: GuardrailEnabledEntry & { supports_runtime_enforcement?: boolean; name?: string }): void {
    if (!entry.supports_runtime_enforcement) {
      flashToast(`${entry.name ?? entry.entry_id} is catalog-only`);
      return;
    }
    const current = guardrailEnabledRef.current?.entries ?? [];
    const enabled = current.some(
      (item) =>
        item.provider_id === entry.provider_id && item.entry_id === entry.entry_id,
    );
    const next = enabled
      ? current.filter(
          (item) =>
            !(item.provider_id === entry.provider_id && item.entry_id === entry.entry_id),
        )
      : [...current, { provider_id: entry.provider_id, entry_id: entry.entry_id }];
    flushSync(() => setGuardrailEnabled({ entries: next }));
    api.saveGuardrailEnabled(next)
      .then((saved) => {
        flushSync(() => setGuardrailEnabled(saved));
        flashToast(
          `${entry.name ?? entry.entry_id} ${enabled ? "disabled" : "enabled"}`,
        );
      })
      .catch((err) => {
        flushSync(() => setGuardrailEnabled({ entries: current }));
        flashToast(`guardrail toggle failed: ${truncate(err.message, 80)}`);
      });
  }

  async function runFalsePositiveFlow(entry: LedgerEntry): Promise<void> {
    try {
      const c = await api.falsePositiveCase(entry.seq, false);
      const yaml = await runEditor(
        defaultFalsePositiveReplacementYAML(c),
        `agentlock-false-positive-${entry.seq}.yaml`,
      );
      if (!yaml) {
        flashToast("false-positive edit cancelled");
        return;
      }
      const validation = await api.falsePositiveValidate({
        case: c,
        replacement_yaml: yaml,
      });
      if (!validation.ok) {
        flashToast(`replacement invalid: ${(validation.errors ?? []).join("; ")}`);
        return;
      }
      const applied = await api.falsePositiveApply({
        case: c,
        replacement_yaml: yaml,
      });
      flashToast(`disabled ${applied.disabled_id}; added ${applied.replacement_id}`);
      refreshPolicy();
    } catch (err) {
      flashToast(
        `false-positive failed: ${truncate(err instanceof Error ? err.message : String(err), 80)}`,
      );
    }
  }

  // Keyboard handler. One handler covers every tab; the dispatch tree
  // is roughly: editor active → ignore; modal open → modal-specific
  // keys; filter editing → text input; otherwise tab-specific keys
  // then the global keys.
  const renderer = useRenderer();
  useEffect(() => {
    const kh = renderer.keyInput;
    if (!kh) return;
    const handler = (e: KeyEvent): void => {
      if (editorActiveRef.current) return;
      const name = e.name;
      const t = tabRef.current;

      // ---- Modal: event detail ----
      if (detailSeqRef.current !== null) {
        if (name === "f") {
          const entry = eventsRef.current.find((ev) => ev.seq === detailSeqRef.current);
          if (entry && canReportFalsePositive(entry)) {
            void runFalsePositiveFlow(entry);
          } else {
            flashToast("false-positive action unavailable for this row");
          }
          return;
        }
        if (name === "escape" || name === "q" || name === "return" || name === "enter") {
          flushSync(() => setDetailSeq(null));
          return;
        }
        if (name === "H") {
          flushSync(() => setExpandHashes((v) => !v));
          return;
        }
        return;
      }

      // ---- Modal: gate detail ----
      if (gateDetailIdRef.current !== null) {
        if (name === "escape" || name === "q" || name === "return" || name === "enter") {
          flushSync(() => {
            setGateDetailId(null);
            setGateDetailScroll(0);
          });
          return;
        }
        if (name === "down" || name === "j") {
          flushSync(() => setGateDetailScroll((v) => v + 1));
          return;
        }
        if (name === "up" || name === "k") {
          flushSync(() => setGateDetailScroll((v) => Math.max(0, v - 1)));
          return;
        }
        return;
      }

      // ---- Filter edit ----
      if (filterFieldRef.current !== null) {
        const activeField = filterFieldRef.current;
        if (name === "escape") {
          flushSync(() => {
            setFilterField(null);
            setFilterBuffer("");
          });
          return;
        }
        if (name === "return" || name === "enter") {
          flushSync(() => {
            if (activeField === "rule") {
              setFilters((cur) => ({ ...cur, rule: filterBufferRef.current }));
            }
            setFilterField(null);
            setFilterBuffer("");
            setCursor((s) => ({ ...s, events: 0 }));
            setScroll((s) => ({ ...s, events: 0 }));
          });
          return;
        }
        if (name === "tab") {
          // Save the current text field, then hop to the next filter.
          const idx = FILTER_FIELDS.indexOf(activeField);
          const nextField = FILTER_FIELDS[(idx + 1) % FILTER_FIELDS.length]!;
          flushSync(() => {
            if (activeField === "rule") {
              setFilters((c) => ({ ...c, rule: filterBufferRef.current }));
            }
            setFilterField(nextField);
            setFilterBuffer(nextField === "rule" ? (filtersRef.current.rule ?? "") : "");
            setCursor((s) => ({ ...s, events: 0 }));
            setScroll((s) => ({ ...s, events: 0 }));
          });
          return;
        }
        if (isCategoricalFilter(activeField) && (name === "left" || name === "h")) {
          cycleEventFilter(activeField, -1);
          return;
        }
        if (isCategoricalFilter(activeField) && (name === "right" || name === "l")) {
          cycleEventFilter(activeField, 1);
          return;
        }
        if (isCategoricalFilter(activeField) && (name === "backspace" || name === "delete")) {
          flushSync(() => {
            setFilters((cur) => ({ ...cur, [activeField]: "" }));
            setCursor((s) => ({ ...s, events: 0 }));
            setScroll((s) => ({ ...s, events: 0 }));
          });
          return;
        }
        if (activeField !== "rule") return;
        if (name === "backspace") {
          flushSync(() => setFilterBuffer((s) => s.slice(0, -1)));
          return;
        }
        // Accumulate any printable character.
        const ch = e.sequence;
        if (ch && ch.length === 1 && ch.charCodeAt(0) >= 32) {
          flushSync(() => setFilterBuffer((s) => s + ch));
          return;
        }
        return;
      }

      // ---- Global keys ----
      if (name === "q" || name === "escape") return onQuit();
      if (name === "left" || name === "h") {
        const idx = TABS.findIndex((tt) => tt.value === t);
        const next = TABS[(idx - 1 + TABS.length) % TABS.length];
        if (next) flushSync(() => setTab(next.value));
        return;
      }
      if (name === "right" || name === "l") {
        const idx = TABS.findIndex((tt) => tt.value === t);
        const next = TABS[(idx + 1) % TABS.length];
        if (next) flushSync(() => setTab(next.value));
        return;
      }
      if (name === "down" || name === "j") {
        moveCursor(1);
        return;
      }
      if (name === "up" || name === "k") {
        moveCursor(-1);
        return;
      }
      if (name === "r") {
        api.getMode().then((r) => flushSync(() => setMode(r))).catch(() => {});
        api.listSessions().then((r) => flushSync(() => setSessions(r))).catch(() => {});
        api.policyView().then((r) => flushSync(() => setPolicy(r))).catch(() => {});
        refreshGuardrails();
        api.ledgerRoot().then((r) => flushSync(() => setLedgerRoot(r))).catch(() => {});
        api.ledgerInsights(statsWindowRef.current)
          .then((r) => flushSync(() => setInsights(r)))
          .catch(() => {});
        flashToast("refreshed");
        return;
      }
      if (name === "m") {
        const m = modeRef.current;
        if (!m) {
          flashToast("mode unknown; waiting for daemon response");
          return;
        }
        const next: "firewall" | "monitor" =
          m.mode === "firewall" ? "monitor" : "firewall";
        api.patchMode(next)
          .then((r) => {
            flushSync(() => setMode(r));
            flashToast(`mode → ${r.mode}`);
          })
          .catch((err) => flashToast(`mode flip failed: ${err.message}`));
        return;
      }

      // ---- Tab-specific ----
      if (t === "stats") {
        if (name === "1") {
          flushSync(() => setStatsWindow("1h"));
          return;
        }
        if (name === "2") {
          flushSync(() => setStatsWindow("24h"));
          return;
        }
        if (name === "3") {
          flushSync(() => setStatsWindow("7d"));
          return;
        }
        if (name === "0") {
          flushSync(() => setStatsWindow("all"));
          return;
        }
        return;
      }

      if (t === "events") {
        if (name === "return" || name === "enter") {
          const list = filteredEvents();
          const cur = cursorRef.current.events;
          const sel = list[cur];
          if (sel) flushSync(() => setDetailSeq(sel.seq));
          return;
        }
        if (name === "f") {
          flushSync(() => {
            setFilterField("source");
            setFilterBuffer("");
          });
          return;
        }
        if (name === "c") {
          flushSync(() => {
            setFilters(EMPTY_FILTERS);
            setCursor((s) => ({ ...s, events: 0 }));
            setScroll((s) => ({ ...s, events: 0 }));
          });
          flashToast("filters cleared");
          return;
        }
        if (name === "i") {
          flushSync(() =>
            setFilters((f) => ({ ...f, internal: !f.internal })),
          );
          return;
        }
        if (name === "o") {
          flushSync(() =>
            setFilters((f) => ({ ...f, outcomes: !f.outcomes })),
          );
          return;
        }
        return;
      }

      if (t === "guardrails") {
        const entries = visibleGuardrails();
        const cur = cursorRef.current.guardrails;
        const sel = entries[cur];
        if (name === "space" || e.sequence === " ") {
          if (!sel) {
            flashToast("no guardrail selected");
            return;
          }
          toggleGuardrail(sel);
          return;
        }
        return;
      }

      if (t === "sessions") {
        if (name === "i") {
          flushSync(() => {
            setShowInternal((v) => !v);
            setCursor((s) => ({ ...s, sessions: 0 }));
            setScroll((s) => ({ ...s, sessions: 0 }));
          });
          return;
        }
        return;
      }

      if (t === "gates") {
        const gates = policyRef.current?.gates ?? [];
        const cur = cursorRef.current.gates;
        const sel = gates[cur];
        if (name === "return" || name === "enter") {
          if (sel) {
            flushSync(() => {
              setGateDetailId(sel.id);
              setGateDetailScroll(0);
            });
          }
          return;
        }
        if (name === "a") {
          // Add via $EDITOR. Spawned async; the handler returns
          // immediately so the renderer can suspend cleanly.
          (async () => {
            const yaml = await runEditor(NEW_GATE_TEMPLATE, "agentlock-new-gate.yaml");
            if (!yaml) {
              flashToast("add cancelled");
              return;
            }
            try {
              const r = await api.installGateYAML(yaml, false);
              flashToast(`added gate; ${r.gates} loaded`);
              refreshPolicy();
            } catch (err) {
              flashToast(
                `add failed: ${truncate(err instanceof Error ? err.message : String(err), 80)}`,
              );
            }
          })();
          return;
        }
        if (name === "e") {
          if (!sel) return;
          (async () => {
            const seed = serializeGateForEdit(sel);
            const yaml = await runEditor(seed, `agentlock-${sel.id}.yaml`);
            if (!yaml) {
              flashToast("edit cancelled");
              return;
            }
            try {
              const r = await api.installGateYAML(yaml, true);
              flashToast(`updated gate; ${r.gates} loaded`);
              refreshPolicy();
            } catch (err) {
              flashToast(
                `edit failed: ${truncate(err instanceof Error ? err.message : String(err), 80)}`,
              );
            }
          })();
          return;
        }
        if (name === "space" || e.sequence === " ") {
          if (!sel) return;
          const next = !sel.disabled;
          api.patchGate(sel.id, { disabled: next })
            .then(() => {
              flashToast(`${sel.id} ${next ? "disabled" : "enabled"}`);
              refreshPolicy();
            })
            .catch((err) => flashToast(`toggle failed: ${err.message}`));
          return;
        }
        if (name === "M") {
          if (!sel) return;
          const cycle = ["inherit", "monitor", "enforce"];
          const idx = Math.max(0, cycle.indexOf(sel.mode || "inherit"));
          const next = cycle[(idx + 1) % cycle.length]!;
          api.patchGate(sel.id, { mode: next })
            .then(() => {
              flashToast(`${sel.id} mode → ${next}`);
              refreshPolicy();
            })
            .catch((err) => flashToast(`mode change failed: ${err.message}`));
          return;
        }
        if (name === "x") {
          if (!sel) return;
          const now = Date.now();
          const pd = pendingDeleteRef.current;
          if (pd && pd.gateId === sel.id && pd.expiresAt > now) {
            // Confirmed.
            api.deleteGate(sel.id)
              .then(() => {
                flashToast(`deleted ${sel.id}`);
                flushSync(() => setPendingDelete(null));
                refreshPolicy();
              })
              .catch((err) => flashToast(`delete failed: ${err.message}`));
            return;
          }
          flushSync(() =>
            setPendingDelete({ gateId: sel.id, expiresAt: now + 2000 }),
          );
          flashToast(`press x again within 2s to delete ${sel.id}`);
          return;
        }
        return;
      }
    };
    kh.on("keypress", handler);
    return () => {
      kh.off("keypress", handler);
    };
  }, [renderer, api, onQuit]);

  function cycleEventFilter(field: "source" | "verdict", delta: number): void {
    const values = eventFilterOptions(eventsRef.current, field);
    const current = filtersRef.current[field];
    const idx = Math.max(0, values.indexOf(current));
    const next = values[(idx + delta + values.length) % values.length] ?? "";
    flushSync(() => {
      setFilters((cur) => ({ ...cur, [field]: next }));
      setCursor((s) => ({ ...s, events: 0 }));
      setScroll((s) => ({ ...s, events: 0 }));
    });
  }

  // The detail modal needs the actual entry — pull it from the buffer.
  const detailEntry =
    detailSeq === null ? null : events.find((e) => e.seq === detailSeq) || null;
  const gateDetail =
    gateDetailId === null
      ? null
      : policy?.gates.find((g) => g.id === gateDetailId) || null;

  return (
    <box flexDirection="column" padding={1}>
      <Header
        daemonUrl={api.baseUrl}
        daemonOk={daemonOk}
        mode={mode}
        root={ledgerRoot}
      />
      <TabBar active={tab} />
      <box flexDirection="column" flexGrow={1} marginTop={1}>
        {detailEntry ? (
          <DetailModal entry={detailEntry} expandHashes={expandHashes} />
        ) : gateDetail ? (
          <GateDetailModal gate={gateDetail} scroll={gateDetailScroll} />
        ) : tab === "stats" ? (
          <StatsPane data={insights} window={statsWindow} />
        ) : tab === "events" ? (
          <EventsPane
            entries={filteredEvents()}
            allEntries={events}
            cursor={cursor.events}
            scroll={scroll.events}
            sseStatus={sseStatus}
            filters={filters}
            filterField={filterField}
            filterBuffer={filterBuffer}
          />
        ) : tab === "guardrails" ? (
          <GuardrailsPane
            providers={guardrailProviders}
            catalog={guardrailCatalog}
            enabled={guardrailEnabled}
            cursor={cursor.guardrails}
            scroll={scroll.guardrails}
            isEnabled={isGuardrailEnabled}
          />
        ) : tab === "sessions" ? (
          <SessionsPane
            data={sessions}
            visible={visibleSessions()}
            cursor={cursor.sessions}
            scroll={scroll.sessions}
            showInternal={showInternal}
          />
        ) : tab === "gates" ? (
          <GatesPane
            data={policy}
            cursor={cursor.gates}
            scroll={scroll.gates}
            pendingDelete={pendingDelete}
          />
        ) : (
          <ModePane data={mode} />
        )}
      </box>
      <Footer toast={toast} tab={tab} />
    </box>
  );
}

// ---------- header ---------------------------------------------------------

interface HeaderProps {
  daemonUrl: string;
  daemonOk: boolean | null;
  mode: ModeResponse | null;
  root: LedgerRootResponse | null;
}

function Header({ daemonUrl, daemonOk, mode, root }: HeaderProps): React.ReactNode {
  const dot = daemonOk === null ? "?" : daemonOk ? "●" : "○";
  const dotColor = daemonOk === null ? "#888888" : daemonOk ? "#00FF88" : "#FF4455";
  const modeColor = mode?.mode === "monitor" ? "#F5A623" : "#00FF88";
  const modeLabel = mode ? mode.mode.toUpperCase() : "—";
  return (
    <box flexDirection="column" marginBottom={1}>
      <ascii-font text="OPENAGENTLOCK" font="slick" color="#7FE7DC" />
      <box flexDirection="row" marginTop={0}>
        <text fg="#888888">local-first hardening for AI coding agents  </text>
        <text fg={dotColor}>{dot} </text>
        <text fg="#CCCCCC">{daemonUrl}  </text>
        <text fg="#555555">|  mode: </text>
        <text fg={modeColor} attributes={1}>
          {modeLabel}
        </text>
        {root ? (
          <>
            <text fg="#555555">  |  seq </text>
            <text fg="#CCCCCC">{root.seq}</text>
            <text fg="#555555">  count </text>
            <text fg="#CCCCCC">{root.count}</text>
            <text fg="#555555">  root </text>
            <text fg="#7FE7DC">{truncate(root.root, 14)}</text>
          </>
        ) : null}
      </box>
    </box>
  );
}

// ---------- tab bar --------------------------------------------------------

function TabBar({ active }: { active: TabName }): React.ReactNode {
  return (
    <box flexDirection="row">
      {TABS.map((t) => {
        const isActive = t.value === active;
        const fg = isActive ? "#7FE7DC" : "#888888";
        const attrs = isActive ? 1 : 0;
        return (
          <text key={t.value} fg={fg} attributes={attrs}>
            {`  ${isActive ? "▌" : " "} ${t.name}  `}
          </text>
        );
      })}
    </box>
  );
}

// ---------- stats pane -----------------------------------------------------

function StatsPane({
  data,
  window,
}: {
  data: LedgerInsightsResponse | null;
  window: InsightWindow;
}): React.ReactNode {
  if (!data) {
    return <text fg="#888888">loading insights...</text>;
  }
  return (
    <box flexDirection="column">
      <WindowSelector window={window} />
      <box marginTop={1}><CounterRow data={data} /></box>
      {window !== "all" && data.buckets.length > 0 ? (
        <box flexDirection="column">
          <Divider title={`activity over ${window} (bar = volume, color = deny rate)`} />
          <ActivitySparkline buckets={data.buckets} window={window} />
          <TimeAxis buckets={data.buckets} window={window} />
        </box>
      ) : null}
      <Divider title="top deny rules" />
      <TopList items={data.top_rules_deny} color="#FF8855" />
      <Divider title="top deny tools" />
      <TopDenyTools data={data} />
      <Divider title="by source" />
      <SourceRow data={data.by_source} />
      {data.total === 0 ? (
        <box marginTop={1}>
          <text fg="#666666">
            no decisions in the last {window}. waiting for activity.
          </text>
        </box>
      ) : null}
    </box>
  );
}

// WindowSelector renders four buttons with the keybind digit anchored
// to each label — pressing the number on the keyboard switches to
// that window, and putting the digits inline removes the need for a
// separate keybind hint line in the footer.
function WindowSelector({ window }: { window: InsightWindow }): React.ReactNode {
  const items: { key: string; label: string; w: InsightWindow }[] = [
    { key: "1", label: "1h", w: "1h" },
    { key: "2", label: "24h", w: "24h" },
    { key: "3", label: "7d", w: "7d" },
    { key: "0", label: "all", w: "all" },
  ];
  return (
    <box flexDirection="row">
      <text fg="#666666">window:  </text>
      {items.map((it, i) => {
        const active = it.w === window;
        const sep = i > 0 ? "   " : "";
        if (active) {
          return (
            <text key={it.w} fg="#7FE7DC" attributes={1}>
              {`${sep}[${it.key}=${it.label}]`}
            </text>
          );
        }
        return (
          <text key={it.w} fg="#888888">
            {`${sep} ${it.key}=${it.label} `}
          </text>
        );
      })}
    </box>
  );
}

// CounterRow puts total / allow / deny / deny-rate on one line.
// Single-row beats stacked label-over-value because OpenTUI 0.1.107
// collapses sibling <text> children of column boxes onto one line when
// the value width grows past the label width — and shipping a layout
// that breaks at runtime isn't worth saving the four characters.
function CounterRow({ data }: { data: LedgerInsightsResponse }): React.ReactNode {
  const allow = data.by_verdict?.allow ?? 0;
  const deny = data.by_verdict?.deny ?? 0;
  const decisions = allow + deny;
  const allowPct = decisions > 0 ? (allow / decisions) * 100 : 0;
  const denyPct = decisions > 0 ? (deny / decisions) * 100 : 0;
  const denyColor =
    denyPct > 25 ? "#FF4455" : denyPct > 5 ? "#F5A623" : "#7FE7DC";
  return (
    <box flexDirection="row">
      <text fg="#666666">total </text>
      <text fg="#CCCCCC" attributes={1}>{String(data.total)}</text>
      <text fg="#666666">   allow </text>
      <text fg="#00FF88" attributes={1}>{String(allow)}</text>
      <text fg="#555555">{` (${allowPct.toFixed(0)}%)`}</text>
      <text fg="#666666">   deny </text>
      <text fg="#FF4455" attributes={1}>{String(deny)}</text>
      <text fg="#555555">{` (${denyPct.toFixed(1)}%)`}</text>
      <text fg="#666666">   rate </text>
      <text fg={denyColor} attributes={1}>{`${denyPct.toFixed(1)}%`}</text>
    </box>
  );
}

// Divider is a section header with a horizontal rule trailing off to
// give the eye an obvious break between blocks.
function Divider({ title }: { title: string }): React.ReactNode {
  const fillLen = Math.max(4, 64 - title.length);
  return (
    <box flexDirection="row" marginTop={1}>
      <text fg="#7FE7DC" attributes={1}>{`── ${title} `}</text>
      <text fg="#444444">{"─".repeat(fillLen)}</text>
    </box>
  );
}

const SPARK_CHARS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

// ActivitySparkline encodes two signals on one row:
//   - bar height: total volume (allow + deny) for the bucket, scaled
//     against the busiest bucket in the window
//   - bar color:  deny rate for the bucket — green / amber / red bands
// Empty buckets render as a dim middle dot so the row width is stable
// and the user can still see the bucket count. Non-empty buckets use a
// minimum height of ▃ so single events stay visibly distinct from the
// empty baseline even when one bucket dwarfs the rest of the window.
function ActivitySparkline({
  buckets,
  window,
}: {
  buckets: { ts: string; allow: number; deny: number }[];
  window: InsightWindow;
}): React.ReactNode {
  const total = (b: { allow: number; deny: number }): number => b.allow + b.deny;
  const max = buckets.reduce((m, b) => Math.max(m, total(b)), 0);
  // Each cell is 1 char wide for 1h/24h and 2 chars wide for 7d so
  // the seven daily bars feel substantial enough to read.
  const cellWidth = window === "7d" ? 2 : 1;
  const minNonZeroIdx = 2; // ▃ floor for visible-but-small buckets.
  return (
    <box flexDirection="row">
      {buckets.map((b, i) => {
        const t = total(b);
        if (t === 0 || max === 0) {
          return (
            <text key={i} fg="#333333">
              {"·".repeat(cellWidth)}
            </text>
          );
        }
        const scaled = Math.round((t / max) * (SPARK_CHARS.length - 1));
        const idx = Math.max(minNonZeroIdx, Math.min(SPARK_CHARS.length - 1, scaled));
        const glyph = SPARK_CHARS[idx]!;
        const rate = b.deny / t;
        const color =
          rate === 0
            ? "#00FF88"
            : rate < 0.05
              ? "#7FE7DC"
              : rate < 0.25
                ? "#F5A623"
                : "#FF4455";
        return (
          <text key={i} fg={color}>
            {glyph.repeat(cellWidth)}
          </text>
        );
      })}
    </box>
  );
}

// TimeAxis lines up time labels under the sparkline. The goal is to
// always answer "what wall-clock does this bar represent?" without
// crowding the columns:
//   1h  → endpoint labels with HH:MM at "now" (12 cells wide).
//   24h → endpoint + midpoint labels with HH:MM (24 cells wide).
//   7d  → weekday initial under each daily cell, with today highlighted
//         and a "today: <date> HH:MM" annotation on the next line.
function TimeAxis({
  buckets,
  window,
}: {
  buckets: { ts: string }[];
  window: InsightWindow;
}): React.ReactNode {
  if (buckets.length === 0) return null;
  const now = new Date();

  if (window === "7d") {
    // One cell per day → letter-of-week under each bar, today highlit.
    const cellWidth = 2;
    const todayKey = now.toDateString();
    return (
      <box flexDirection="row">
        {buckets.map((b, i) => {
          const d = new Date(b.ts);
          const dow = d.getDay();
          const ch = ["S", "M", "T", "W", "T", "F", "S"][dow] ?? "?";
          const isToday = d.toDateString() === todayKey;
          return (
            <text key={i} fg={isToday ? "#7FE7DC" : "#666666"} attributes={isToday ? 1 : 0}>
              {ch.padEnd(cellWidth, " ")}
            </text>
          );
        })}
      </box>
    );
  }

  // 1h / 24h: just the relative endpoints. Wall-clock lives next to
  // the window button now, so we don't need to repeat HH:MM here.
  const width = buckets.length;
  const left = window === "24h" ? "−24h" : "−60m";
  const right = "now";
  const anchors: { col: number; label: string }[] = [{ col: 0, label: left }];
  if (window === "24h") anchors.push({ col: 12, label: "−12h" });
  anchors.push({ col: Math.max(0, width - right.length), label: right });

  const cells: string[] = Array(width).fill(" ");
  for (const a of anchors) {
    for (let i = 0; i < a.label.length; i++) {
      const idx = a.col + i;
      if (idx >= 0 && idx < cells.length) cells[idx] = a.label[i]!;
    }
  }
  return <text fg="#555555">{cells.join("")}</text>;
}

// TopDenyTools wraps the tools panel with a more honest empty state.
// The `tool` field on ledger entries is recent (added with the schema
// change that introduced this aggregation). Entries written before
// that change have tool="", so they roll up under top_rules_deny but
// not top_tools_deny — leaving a confusing "rule denies exist but
// tool denies don't" picture if we just rendered "(none)".
function TopDenyTools({ data }: { data: LedgerInsightsResponse }): React.ReactNode {
  if (data.top_tools_deny.length > 0) {
    return <TopList items={data.top_tools_deny} color="#FF8855" />;
  }
  const ruleDenyCount = data.top_rules_deny.reduce((s, r) => s + r.count, 0);
  if (ruleDenyCount > 0) {
    return (
      <box flexDirection="column">
        <text fg="#666666">
          {`  no tool field on the ${ruleDenyCount} deny entr${ruleDenyCount === 1 ? "y" : "ies"} in this window.`}
        </text>
        <text fg="#555555">  (these were written before the daemon gained the tool field — fire a fresh deny to populate)</text>
      </box>
    );
  }
  return <text fg="#555555">  (none)</text>;
}

function TopList({
  items,
  color,
}: {
  items: { key: string; count: number }[];
  color: string;
}): React.ReactNode {
  if (!items.length) {
    return <text fg="#555555">  (none)</text>;
  }
  const max = items.reduce((m, it) => Math.max(m, it.count), 1);
  return (
    <box flexDirection="column">
      {items.map((it) => {
        const barLen = Math.max(1, Math.round((it.count / max) * 12));
        return (
          <box key={it.key} flexDirection="row">
            <text fg="#CCCCCC">{`  ${truncate(it.key, 28).padEnd(30, " ")}`}</text>
            <text fg="#666666">{String(it.count).padStart(4, " ")}  </text>
            <text fg={color}>{"█".repeat(barLen)}</text>
          </box>
        );
      })}
    </box>
  );
}

function SourceRow({ data }: { data: Record<string, number> }): React.ReactNode {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return <text fg="#555555">  (none)</text>;
  }
  return (
    <box flexDirection="row">
      {entries.map(([k, v]) => (
        <text key={k} fg="#CCCCCC">{`  ${k}=${v}`}</text>
      ))}
    </box>
  );
}

// ---------- events pane ----------------------------------------------------

interface EventsPaneProps {
  entries: LedgerEntry[];
  allEntries: LedgerEntry[];
  cursor: number;
  scroll: number;
  sseStatus: "connecting" | "open" | "closed";
  filters: Filters;
  filterField: FilterField | null;
  filterBuffer: string;
}

function EventsPane({
  entries,
  allEntries,
  cursor,
  scroll,
  sseStatus,
  filters,
  filterField,
  filterBuffer,
}: EventsPaneProps): React.ReactNode {
  const visible = entries.slice(scroll, scroll + VISIBLE_ROWS);
  const outcomes = filters.outcomes ? outcomeByToolUseId(allEntries) : new Map();
  const statusColor =
    sseStatus === "open" ? "#00FF88" : sseStatus === "closed" ? "#FF4455" : "#F5A623";
  return (
    <box flexDirection="column">
      <box flexDirection="row" marginBottom={1}>
        <text fg={statusColor}>● SSE: {sseStatus}</text>
        <text fg="#555555">    {entries.length} shown (seq DESC)</text>
      </box>
      <FilterBar
        filters={filters}
        field={filterField}
        buffer={filterBuffer}
      />
      {entries.length === 0 ? (
        <text fg="#666666">
          no events match. press c to clear filters or wait for activity.
        </text>
      ) : (
        visible.map((e, i) => {
          const isCursor = scroll + i === cursor;
          const arrow = isCursor ? "▌" : " ";
          const rowFg = isCursor ? "#FFFFFF" : "#CCCCCC";
          const verdictRaw = e.monitor_match ? "alert" : (e.verdict ?? "—");
          const outcome = outcomes.get(e.tool_use_id);
          // Anchoring time at the left matches log-scanning convention
          // and gives the eye a stable column to track. Verdict comes
          // next, bold + uppercase, since it's the highest-signal field.
          // toolu_id strips its constant "toolu_" prefix — every
          // claude-code event carries it, it's pure noise.
          const idShort = e.tool_use_id.startsWith("toolu_")
            ? e.tool_use_id.slice(6)
            : e.tool_use_id;
          return (
            <box key={e.seq} flexDirection="column">
              <box flexDirection="row">
                <text fg={isCursor ? "#7FE7DC" : "#555555"}>
                  {`${arrow} ${String(e.seq).padStart(5, " ")}  `}
                </text>
                <text fg="#888888">{cell(formatTs(e.ts), 8)}</text>
                <text
                  fg={verdictColor(e.verdict, e.monitor_match)}
                  attributes={1}
                >
                  {cell(verdictRaw.toUpperCase(), 7)}
                </text>
                <text fg="#888888">{cell(e.source, 12)}</text>
                <text fg={rowFg}>{cell(e.rule_id || "—", 22)}</text>
                <text fg="#666666">{cell(idShort, 18)}</text>
              </box>
              {outcome ? (
                <box flexDirection="row">
                  <text fg="#555555">{`  ↳ ${String(outcome.seq).padStart(5, " ")}  `}</text>
                  <text fg="#666666">{cell(formatTs(outcome.ts), 8)}</text>
                  <text fg={verdictColor(outcome.verdict, outcome.monitor_match)}>
                    {cell((outcome.verdict === "complete" ? "RAN" : "ERRORED"), 7)}
                  </text>
                  <text fg="#666666">{cell(outcome.source, 12)}</text>
                  <text fg="#666666">{cell("tool outcome", 22)}</text>
                  <text fg="#555555">{cell(idShort, 18)}</text>
                </box>
              ) : null}
            </box>
          );
        })
      )}
    </box>
  );
}

function FilterBar({
  filters,
  field,
  buffer,
}: {
  filters: Filters;
  field: FilterField | null;
  buffer: string;
}): React.ReactNode {
  const cell = (label: FilterField): React.ReactNode => {
    const editing = field === label;
    const current = filters[label] || "all";
    const value = editing
      ? label === "rule"
        ? `${buffer}_`
        : `‹${current}›`
      : current;
    const fg = editing ? "#7FE7DC" : filters[label] ? "#CCCCCC" : "#555555";
    const attrs = editing ? 1 : 0;
    return (
      <text key={label} fg={fg} attributes={attrs}>
        {`  ${label}:[${value}]  `}
      </text>
    );
  };
  return (
    <box flexDirection="row" marginBottom={1}>
      {cell("source")}
      {cell("verdict")}
      {cell("rule")}
      <text fg={filters.internal ? "#7FE7DC" : "#555555"}>
        {`  internal:[${filters.internal ? "on" : "off"}]`}
      </text>
      <text fg={filters.outcomes ? "#7FE7DC" : "#555555"}>
        {`  outcomes:[${filters.outcomes ? "on" : "off"}]`}
      </text>
      {field && field !== "rule" ? (
        <text fg="#555555">  h/l select  tab next  enter done</text>
      ) : field === "rule" ? (
        <text fg="#555555">  type rule text  tab next  enter done</text>
      ) : null}
    </box>
  );
}

function verdictColor(v?: string, monitor?: boolean): string {
  if (monitor) return "#F5A623";
  if (v === "allow") return "#00FF88";
  if (v === "deny") return "#FF4455";
  return "#888888";
}

function isOutcomeEntry(entry: LedgerEntry): boolean {
  return entry.verdict === "complete" || entry.verdict === "failure";
}

function isCategoricalFilter(field: FilterField): field is "source" | "verdict" {
  return field === "source" || field === "verdict";
}

function eventFilterOptions(entries: LedgerEntry[], field: "source" | "verdict"): string[] {
  const values = new Set<string>();
  for (const entry of entries) {
    if (isOutcomeEntry(entry)) continue;
    const value = field === "source" ? entry.source : entry.verdict;
    if (value) values.add(value);
  }
  return ["", ...Array.from(values).sort()];
}

function outcomeByToolUseId(entries: LedgerEntry[]): Map<string, LedgerEntry> {
  const out = new Map<string, LedgerEntry>();
  for (const entry of entries) {
    if (!isOutcomeEntry(entry) || !entry.tool_use_id) continue;
    const current = out.get(entry.tool_use_id);
    if (!current || entry.seq > current.seq) out.set(entry.tool_use_id, entry);
  }
  return out;
}

// ---------- sessions pane --------------------------------------------------

function SessionsPane({
  data,
  visible,
  cursor,
  scroll,
  showInternal,
}: {
  data: SessionsListResponse | null;
  visible: SessionSummary[];
  cursor: number;
  scroll: number;
  showInternal: boolean;
}): React.ReactNode {
  if (!data) {
    return <text fg="#888888">loading sessions...</text>;
  }
  if (visible.length === 0) {
    return (
      <box flexDirection="column">
        <text fg="#888888">
          no sessions{showInternal ? "" : " (i to show internal)"}.
        </text>
      </box>
    );
  }
  const rows = visible.slice(scroll, scroll + VISIBLE_ROWS);
  return (
    <box flexDirection="column">
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">live policy hash: </text>
        <text fg="#CCCCCC">{data.live_policy_hash}</text>
        <text fg="#555555">    internal: </text>
        <text fg={showInternal ? "#7FE7DC" : "#555555"}>
          {showInternal ? "shown" : "hidden"}
        </text>
      </box>
      <box flexDirection="row" marginBottom={1}>
        <text fg="#555555" attributes={1}>
          {"   ID".padEnd(24, " ")}
          {"HARNESS".padEnd(14, " ")}
          {"SIGNER".padEnd(16, " ")}
          {"ACTIVE".padEnd(8, " ")}
          {"NEEDS_RELOAD"}
        </text>
      </box>
      {rows.map((s, i) => {
        const isCursor = scroll + i === cursor;
        const arrow = isCursor ? "▌" : " ";
        return (
          <box key={s.id} flexDirection="row">
            <text fg={isCursor ? "#7FE7DC" : "#CCCCCC"}>
              {`${arrow} ` + truncate(s.id, 22).padEnd(22, " ")}
            </text>
            <text fg="#AAAAAA">{s.harness.padEnd(14, " ")}</text>
            <text fg={signerColor(s.signer)}>{s.signer.padEnd(16, " ")}</text>
            <text fg={s.active ? "#00FF88" : "#888888"}>
              {(s.active ? "yes" : "ended").padEnd(8, " ")}
            </text>
            <text fg={s.needs_reload ? "#F5A623" : "#666666"}>
              {s.needs_reload ? "yes" : "no"}
            </text>
          </box>
        );
      })}
    </box>
  );
}

function signerColor(s: string): string {
  if (s === "yubikey_piv" || s === "yubikey_fido2") return "#00FF88";
  if (s === "os_keychain") return "#7FE7DC";
  if (s === "totp_backed_software") return "#F5A623";
  if (s === "none" || s === "software") return "#FF8888";
  return "#AAAAAA";
}

function GuardrailsPane({
  providers,
  catalog,
  enabled,
  cursor,
  scroll,
  isEnabled,
}: {
  providers: GuardrailProvidersResponse | null;
  catalog: GuardrailCatalogResponse | null;
  enabled: GuardrailEnabledResponse | null;
  cursor: number;
  scroll: number;
  isEnabled: (entry: { provider_id: string; entry_id: string }) => boolean;
}): React.ReactNode {
  if (!providers) {
    return <text fg="#888888">loading guardrails...</text>;
  }
  const entries = catalog?.entries ?? [];
  const providerErrors = catalog?.provider_errors ?? [];
  const enabledCount = enabled?.entries.length ?? 0;
  const rows = entries.slice(scroll, scroll + VISIBLE_ROWS);
  return (
    <box flexDirection="column">
      <Divider title="providers" />
      {providers.providers.length === 0 ? (
        <text fg="#888888">no providers registered</text>
      ) : (
        providers.providers.map((p) => (
          <box key={p.id} flexDirection="column">
            <box flexDirection="row">
              <text fg={p.configured ? "#7FE7DC" : "#888888"}>
                {p.name.padEnd(14, " ")}
              </text>
              <text fg={p.configured ? "#00FF88" : "#F5A623"}>
                {(p.configured ? "configured" : "not configured").padEnd(16, " ")}
              </text>
              <text fg="#666666">{p.capabilities.join(" / ")}</text>
            </box>
            <text fg="#666666">
              {p.id === "nvidia"
                ? "runtime classifier after local allow"
                : p.id === "openrouter"
                  ? "catalog only in this slice; no runtime classifier yet"
                  : "provider behavior depends on runtime support"}
            </text>
          </box>
        ))
      )}
      {providerErrors.length > 0 ? (
        <>
          <Divider title="provider errors" />
          {providerErrors.map((item) => (
            <box key={item.provider_id} flexDirection="row">
              <text fg="#F5A623">{item.provider_id.padEnd(14, " ")}</text>
              <text fg="#FF8888">{truncate(item.detail, 96)}</text>
            </box>
          ))}
        </>
      ) : null}
      <Divider title="catalog" />
      <box flexDirection="row" marginBottom={1}>
        <text fg="#666666">{`${enabledCount} runtime guardrail${enabledCount === 1 ? "" : "s"} enabled`}</text>
      </box>
      {entries.length === 0 ? (
        <text fg="#888888">no catalog entries</text>
      ) : (
        <>
          <box flexDirection="row" marginBottom={1}>
            <text fg="#555555" attributes={1}>
              {"ON".padEnd(4, " ")}
              {"PROVIDER".padEnd(14, " ")}
              {"KIND".padEnd(18, " ")}
              {"RUNTIME".padEnd(10, " ")}
              {"ENTRY"}
            </text>
          </box>
          {rows.map((entry, index) => {
            const selected = scroll + index === cursor;
            const marker = selected ? "▌" : " ";
            const active = isEnabled(entry);
            return (
            <box key={`${entry.provider_id}/${entry.entry_id}`} flexDirection="row">
              <text fg={selected ? "#7FE7DC" : "#555555"}>{`${marker}${active ? "[x]" : "[ ]"}`.padEnd(4, " ")}</text>
              <text fg={selected ? "#CCCCCC" : "#AAAAAA"}>{entry.provider_id.padEnd(14, " ")}</text>
              <text fg={entry.kind === "classifier_model" ? "#7FE7DC" : "#F5A623"}>
                {(entry.kind === "classifier_model" ? "classifier" : "policy").padEnd(18, " ")}
              </text>
              <text fg={entry.supports_runtime_enforcement ? "#00FF88" : "#888888"}>
                {(entry.supports_runtime_enforcement ? "yes" : "no").padEnd(10, " ")}
              </text>
              <text fg={selected ? "#FFFFFF" : "#CCCCCC"}>{truncate(entry.name || entry.entry_id, 56)}</text>
            </box>
          )})}
          {entries.length > VISIBLE_ROWS ? (
            <box marginTop={1}>
              <text fg="#666666">{`rows ${scroll + 1}-${Math.min(entries.length, scroll + VISIBLE_ROWS)} of ${entries.length}`}</text>
            </box>
          ) : null}
        </>
      )}
    </box>
  );
}

const INTERNAL_SOURCES = new Set<string>([
  "internal",
  "agentlock",
  "",
]);
const INTERNAL_HARNESSES = new Set<string>([
  "internal",
  "agentlock",
  "",
]);

// ---------- gates pane -----------------------------------------------------

function GatesPane({
  data,
  cursor,
  scroll,
  pendingDelete,
}: {
  data: PolicyViewResponse | null;
  cursor: number;
  scroll: number;
  pendingDelete: { gateId: string; expiresAt: number } | null;
}): React.ReactNode {
  if (!data) {
    return <text fg="#888888">loading policy...</text>;
  }
  const rows: PolicyGateView[] = data.gates.slice(scroll, scroll + VISIBLE_ROWS);
  return (
    <box flexDirection="column">
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">hash: </text>
        <text fg="#CCCCCC">{truncate(data.hash, 40)}</text>
        <text fg="#555555">    policy_mode: </text>
        <text fg="#CCCCCC">{data.policy_mode}</text>
        <text fg="#555555">    gates: </text>
        <text fg="#CCCCCC">{data.gates.length}</text>
      </box>
      {rows.map((g, i) => {
        const isCursor = scroll + i === cursor;
        const arrow = isCursor ? "▌" : g.disabled ? "-" : "•";
        const arrowFg = isCursor ? "#7FE7DC" : g.disabled ? "#555555" : "#CCCCCC";
        const idFg = isCursor ? "#FFFFFF" : g.disabled ? "#555555" : "#CCCCCC";
        const armed =
          pendingDelete?.gateId === g.id &&
          pendingDelete.expiresAt > Date.now();
        return (
          <box key={g.id} flexDirection="row">
            <text fg={arrowFg}>{`  ${arrow} `}</text>
            <text fg={idFg}>{g.id.padEnd(36, " ")}</text>
            <text fg="#888888">{(g.mode || "—").padEnd(10, " ")}</text>
            <text fg="#888888">
              {truncate(gateToolSummary(g), 18).padEnd(20, " ")}
            </text>
            <text fg="#555555">
              {gateMatchSummary(g)}
            </text>
            {armed ? (
              <text fg="#FF4455" attributes={1}>{"  ← x to confirm"}</text>
            ) : null}
          </box>
        );
      })}
    </box>
  );
}

function gateToolSummary(g: PolicyGateView): string {
  const match = g.match;
  if (match?.any_of && match.any_of.length > 0) {
    const tools = match.any_of
      .map((sub) => sub.tool ?? sub.tool_prefix)
      .filter((value): value is string => !!value);
    return tools.length > 0 ? tools.join("|") : "any_of";
  }
  return match?.tool ?? match?.tool_prefix ?? g.tool ?? g.tool_prefix ?? "*";
}

function gateMatchSummary(g: PolicyGateView): string {
  const regexes = commandRegexesFromMatch(g.match);
  if (regexes.length === 0) regexes.push(...(g.any_command_regex ?? []));
  if (regexes.length > 0) return `regex×${regexes.length}`;
  return (g.evaluators ?? []).join(",");
}

function commandRegexesFromMatch(match: PolicyMatchView | undefined): string[] {
  if (!match) return [];
  return [
    ...(match.any_command_regex ?? []),
    ...((match.any_of ?? []).flatMap((sub) => commandRegexesFromMatch(sub))),
  ];
}

// ---------- mode pane ------------------------------------------------------

function ModePane({ data }: { data: ModeResponse | null }): React.ReactNode {
  if (!data) {
    return <text fg="#888888">loading mode...</text>;
  }
  const effective = data.mode;
  const envSet = !!data.env && data.env !== "";
  const overrideSet = !!data.runtime_override && data.runtime_override !== "";
  return (
    <box flexDirection="column">
      <box flexDirection="column" marginBottom={1}>
        <text fg="#888888">Daemon-wide enforcement posture. Press </text>
        <text fg="#7FE7DC" attributes={1}>m</text>
        <text fg="#888888"> to flip the runtime override.</text>
      </box>
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">effective:  </text>
        <text
          fg={effective === "monitor" ? "#F5A623" : "#00FF88"}
          attributes={1}
        >
          {effective.toUpperCase()}
        </text>
      </box>
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">env       : </text>
        <text fg={envSet ? "#CCCCCC" : "#555555"}>
          {envSet ? data.env : "(unset)"}
        </text>
      </box>
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">override  : </text>
        <text fg={overrideSet ? "#7FE7DC" : "#555555"}>
          {overrideSet ? data.runtime_override : "(none)"}
        </text>
      </box>
      <text fg="#555555">
        monitor = log-only; firewall = enforce deny. Precedence: runtime override
        &gt; env &gt; default (firewall).
      </text>
    </box>
  );
}

// ---------- detail modals --------------------------------------------------

const GATE_DETAIL_VISIBLE_ROWS = 14;
const GATE_DETAIL_LINE_WIDTH = 112;

function GateDetailModal({
  gate,
  scroll,
}: {
  gate: PolicyGateView;
  scroll: number;
}): React.ReactNode {
  const schemaRows = gateSchemaRows(gate.match);
  const maxScroll = Math.max(0, schemaRows.length - GATE_DETAIL_VISIBLE_ROWS);
  const safeScroll = Math.min(scroll, maxScroll);
  const visibleRows = schemaRows.slice(
    safeScroll,
    safeScroll + GATE_DETAIL_VISIBLE_ROWS,
  );
  return (
    <box flexDirection="column" borderStyle="rounded" borderColor="#7FE7DC" padding={1}>
      <text fg="#7FE7DC" attributes={1}>{`gate detail — ${gate.id}`}</text>
      <box flexDirection="row" marginTop={1}>
        <text fg="#888888">mode: </text>
        <text fg="#CCCCCC">{gate.mode || "inherit"}</text>
        <text fg="#555555">   source: </text>
        <text fg="#CCCCCC">{gate.source || "daemon"}</text>
        <text fg="#555555">   enabled: </text>
        <text fg={gate.disabled ? "#FF8888" : "#00FF88"}>
          {gate.disabled ? "no" : "yes"}
        </text>
      </box>
      <box flexDirection="row">
        <text fg="#888888">tool: </text>
        <text fg="#CCCCCC">{gateToolSummary(gate)}</text>
        <text fg="#555555">   tool_prefix: </text>
        <text fg="#CCCCCC">{gate.match?.tool_prefix ?? gate.tool_prefix ?? "—"}</text>
      </box>
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">evaluators: </text>
        <text fg="#CCCCCC">{(gate.evaluators ?? []).join(", ") || "—"}</text>
      </box>
      <box flexDirection="row">
        <text fg="#888888" attributes={1}>match schema</text>
        <text fg="#555555">
          {schemaRows.length > GATE_DETAIL_VISIBLE_ROWS
            ? `  rows ${safeScroll + 1}-${Math.min(schemaRows.length, safeScroll + GATE_DETAIL_VISIBLE_ROWS)} of ${schemaRows.length}`
            : ""}
        </text>
      </box>
      {visibleRows.length > 0 ? (
        visibleRows.map((row, index) => (
          <text key={`${safeScroll}-${index}`} fg={row.fg}>
            {truncate(row.text, GATE_DETAIL_LINE_WIDTH)}
          </text>
        ))
      ) : (
        <text fg="#555555">—</text>
      )}
      <box marginTop={1}>
        <text fg="#555555">
          {schemaRows.length > GATE_DETAIL_VISIBLE_ROWS ? "↑/↓ or j/k scroll  " : ""}
          enter/esc closes
        </text>
      </box>
    </box>
  );
}

function gateSchemaRows(match: PolicyMatchView | undefined): Array<{ text: string; fg: string }> {
  const rows: Array<{ text: string; fg: string }> = [];
  for (const { label, match: branch } of matchBranches(match)) {
    rows.push({ text: label, fg: "#7FE7DC" });
    pushMatchSchemaRows(rows, branch);
  }
  return rows;
}

function pushMatchSchemaRows(
  rows: Array<{ text: string; fg: string }>,
  match: PolicyMatchView,
): void {
  const start = rows.length;
  if (match.tool) rows.push({ text: `  tool: ${match.tool}`, fg: "#CCCCCC" });
  if (match.tool_prefix)
    rows.push({ text: `  tool_prefix: ${match.tool_prefix}`, fg: "#CCCCCC" });
  if (match.path_glob_regex)
    rows.push({ text: `  path_glob_regex: ${match.path_glob_regex}`, fg: "#CCCCCC" });
  pushRegexRows(rows, "any_command_regex", match.any_command_regex);
  pushRegexRows(rows, "any_path_regex", match.any_path_regex);
  pushRegexRows(rows, "any_url_regex", match.any_url_regex);
  if (rows.length === start) rows.push({ text: "  —", fg: "#555555" });
}

function pushRegexRows(
  rows: Array<{ text: string; fg: string }>,
  label: string,
  values?: string[],
): void {
  if (!values || values.length === 0) return;
  rows.push({ text: `  ${label}:`, fg: "#888888" });
  for (const value of values) {
    rows.push({ text: `    - ${value}`, fg: "#CCCCCC" });
  }
}

function matchBranches(
  match: PolicyMatchView | undefined,
): Array<{ label: string; match: PolicyMatchView }> {
  if (!match) return [];
  if (match.any_of && match.any_of.length > 0) {
    return match.any_of.map((sub, index) => ({
      label: `any_of[${index}]`,
      match: sub,
    }));
  }
  return [{ label: "match", match }];
}

function DetailModal({
  entry,
  expandHashes,
}: {
  entry: LedgerEntry;
  expandHashes: boolean;
}): React.ReactNode {
  const hashFmt = (h?: string): string => {
    if (!h) return "—";
    if (expandHashes) return h;
    if (h.length <= 16) return h;
    return `${h.slice(0, 8)}…${h.slice(-8)}`;
  };
  const subject = subjectFromLedgerEntry(entry);
  return (
    <box
      flexDirection="column"
      marginTop={1}
      borderStyle="single"
      borderColor="#7FE7DC"
      padding={1}
    >
      <text fg="#7FE7DC" attributes={1}>{`event detail — seq ${entry.seq}`}</text>
      <Row k="ts" v={entry.ts} />
      <Row k="source" v={entry.source} />
      {subject ? <Row k={subject.label} v={subject.value} /> : null}
      <Row k="rule_id" v={entry.rule_id || "—"} />
      <Row
        k="verdict"
        v={`${entry.verdict || "—"}${entry.monitor_match ? " (monitor match)" : ""}`}
      />
      <Row k="tool" v={entry.tool || "—"} />
      <Row k="tool_use_id" v={entry.tool_use_id} />
      <Row k="signer" v={entry.signer} />
      <Row k="payload_hash" v={hashFmt(entry.payload_hash)} />
      <Row k="leaf_hash" v={hashFmt(entry.leaf_hash)} />
      <Row k="prev_leaf" v={hashFmt(entry.prev_leaf)} />
      <Row k="sig" v={hashFmt(entry.sig)} />
      <text fg="#555555">
        {`  H toggle full hashes${canReportFalsePositive(entry) ? "   f report false positive" : ""}   esc/enter close`}
      </text>
    </box>
  );
}

function canReportFalsePositive(entry: LedgerEntry): boolean {
  return (
    Boolean(entry.rule_id) &&
    entry.rule_id !== "default" &&
    !isOutcomeEntry(entry) &&
    (entry.verdict === "deny" || Boolean(entry.monitor_match))
  );
}

function defaultFalsePositiveReplacementYAML(c: FalsePositiveCaseResponse): string {
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

function subjectFromLedgerEntry(
  entry: LedgerEntry,
): { label: "command" | "path" | "url"; value: string } | null {
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

function stringField(input: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return null;
}

function Row({ k, v }: { k: string; v: string }): React.ReactNode {
  return (
    <box flexDirection="row">
      <text fg="#888888">{k.padEnd(14, " ")}: </text>
      <text fg="#CCCCCC">{v}</text>
    </box>
  );
}

// ---------- footer ---------------------------------------------------------

function Footer({ toast, tab }: { toast: string; tab: TabName }): React.ReactNode {
  if (toast) {
    return (
      <box marginTop={1}>
        <text fg="#7FE7DC">{toast}</text>
      </box>
    );
  }
  const common = "h/l tab  j/k move  m flip mode  r refresh  q quit";
  const tabHelp: Record<TabName, string> = {
    stats: "(window keybinds shown next to each button above)",
    events: "enter detail  f filter  c clear  i internal  o outcomes  H hashes",
    guardrails: "space toggle runtime guardrail  r refresh  startup env on control plane",
    sessions: "i toggle internal harnesses",
    gates: "enter detail  a add  e edit  space toggle  M cycle-mode  x x delete",
    mode: "(read-only — m on any tab flips mode)",
  };
  // Each line wrapped in its own row-box. Bare <text> siblings inside
  // a column box can collapse onto one line in OpenTUI 0.1.107 once
  // the content gets wide enough — the boxing forces real row breaks.
  return (
    <box flexDirection="column" marginTop={1}>
      <box flexDirection="row">
        <text fg="#666666">{tabHelp[tab]}</text>
      </box>
      <box flexDirection="row">
        <text fg="#555555">{common}</text>
      </box>
    </box>
  );
}

// ---------- utilities ------------------------------------------------------

function truncate(s: string, n: number): string {
  if (!s) return "";
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

// cell renders a fixed-width column for the events log: truncates when
// content is too long, pads when it's too short, and always appends a
// two-space gap so adjacent <text> nodes don't smash together when the
// renderer collapses leading whitespace, and so the columns have room
// to breathe.
function cell(s: string, n: number): string {
  return truncate(s ?? "", n).padEnd(n, " ") + "  ";
}

function formatTs(ts: string): string {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return ts;
  }
}

// serializeGateForEdit reconstructs an editable YAML form of a single
// gate from its policy view. The result is a complete YAML document
// suitable for re-submitting via installGateYAML(replace=true). Fields
// the daemon doesn't expose in the view (e.g. evaluators with their
// original parameters) round-trip as a comment so the user can rebuild
// them by hand if needed.
function serializeGateForEdit(g: PolicyGateView): string {
  const obj: Record<string, unknown> = { id: g.id };
  if (g.mode) obj.mode = g.mode;
  if (g.disabled) obj.disabled = true;
  const match: Record<string, unknown> = {};
  if (g.tool) match.tool = g.tool;
  if (g.tool_prefix) match.tool_prefix = g.tool_prefix;
  if (g.any_command_regex && g.any_command_regex.length > 0)
    match.any_command_regex = g.any_command_regex;
  if (Object.keys(match).length > 0) obj.match = match;
  // Evaluators come back as type names only (e.g. ["always"]); we
  // can't faithfully round-trip parameters, so emit a stub that the
  // user can fill in.
  if (g.evaluators && g.evaluators.length > 0) {
    obj.evaluate = g.evaluators.map((kind) => ({ kind }));
  }
  const header =
    "# Editing existing gate. Save to apply (replace=true);\n" +
    "# close without saving to abort. Evaluator parameters\n" +
    "# (allowlists, host lists, etc.) are not exposed by the\n" +
    "# /v1/policy/view endpoint — re-add them here if needed.\n";
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const yaml = require("yaml") as { stringify(o: unknown): string };
  return header + yaml.stringify(obj);
}

// ---------- entrypoint -----------------------------------------------------

export async function runDashboardTUI(api: ApiClient): Promise<void> {
  const renderer = await createCliRenderer({ exitOnCtrlC: true });
  renderer.start();
  const root = createRoot(renderer);
  await new Promise<void>((resolve) => {
    const finish = (): void => {
      try {
        root.unmount();
      } catch {
        // best-effort
      }
      try {
        renderer.destroy();
      } catch {
        // best-effort
      }
      resolve();
    };
    root.render(<Dashboard api={api} onQuit={finish} />);
  });
}
