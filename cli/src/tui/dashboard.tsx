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
//   Events:  enter open detail   f filter   c clear filters   tab cycle field   H toggle full hashes
//   Gates:   a add (editor)   e edit (editor)   space toggle disabled   M cycle mode   x x delete
//   Sessions: i toggle internal harnesses
//
// The daemon base URL comes from the ApiClient passed in (so tests can
// point at a Bun.serve() mock and the real CLI points at 127.0.0.1:7878).

import { createCliRenderer, type KeyEvent } from "@opentui/core";
import { createRoot, flushSync, useRenderer } from "@opentui/react";
import { useEffect, useRef, useState } from "react";
import type {
  ApiClient,
  InsightWindow,
  LedgerInsightsResponse,
  LedgerRootResponse,
  ModeResponse,
  PolicyGateView,
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
  rule_id?: string;
  verdict?: string;
  monitor_match?: boolean;
  payload_hash?: string;
  sig?: string;
  leaf_hash?: string;
  prev_leaf?: string;
}

type TabName = "stats" | "events" | "sessions" | "gates" | "mode";

const TABS: { name: string; description: string; value: TabName }[] = [
  { name: "Stats", description: "Operational insights", value: "stats" },
  { name: "Events", description: "Live ledger tail", value: "events" },
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
}
const EMPTY_FILTERS: Filters = {
  source: "",
  verdict: "",
  rule: "",
  internal: false,
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
    sessions: 0,
    gates: 0,
    mode: 0,
  });
  const [scroll, setScroll] = useState<Record<TabName, number>>({
    stats: 0,
    events: 0,
    sessions: 0,
    gates: 0,
    mode: 0,
  });
  const [daemonOk, setDaemonOk] = useState<boolean | null>(null);
  const [mode, setMode] = useState<ModeResponse | null>(null);
  const [sessions, setSessions] = useState<SessionsListResponse | null>(null);
  const [policy, setPolicy] = useState<PolicyViewResponse | null>(null);
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

  // Editor flow state — when true, the renderer is suspended and
  // keypresses skip the TUI handler (the editor owns the TTY).
  const editorActiveRef = useRef<boolean>(false);

  // Polling: health, mode, sessions, policy, ledger root.
  useInterval(() => {
    api.health().then(() => setDaemonOk(true)).catch(() => setDaemonOk(false));
    api.getMode().then(setMode).catch(() => {});
    api.listSessions().then(setSessions).catch(() => {});
    api.policyView().then(setPolicy).catch(() => {});
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
  const showInternalRef = useRef(showInternal);
  showInternalRef.current = showInternal;
  const pendingDeleteRef = useRef(pendingDelete);
  pendingDeleteRef.current = pendingDelete;
  const statsWindowRef = useRef(statsWindow);
  statsWindowRef.current = statsWindow;

  // Filtered/visible derivations used by the keyboard handler when
  // computing what's "under the cursor."
  function filteredEvents(): LedgerEntry[] {
    const f = filtersRef.current;
    let arr = eventsRef.current;
    if (f.source) arr = arr.filter((e) => e.source.includes(f.source));
    if (f.verdict)
      arr = arr.filter((e) => (e.verdict || "").includes(f.verdict));
    if (f.rule) arr = arr.filter((e) => (e.rule_id || "").includes(f.rule));
    if (!f.internal) {
      // "internal" off = decisions only. Hides:
      //   - post-tool-use receipts (verdict=failure, no rule_id) that
      //     pair with every allow/deny and just doubled the row count.
      //   - session lifecycle rows (session.unattested, auto-create) that
      //     come from internal sources or carry no rule_id.
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

  function moveCursor(delta: number): void {
    const t = tabRef.current;
    let max = 0;
    if (t === "events") max = filteredEvents().length;
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

      // ---- Filter line-edit ----
      if (filterFieldRef.current !== null) {
        if (name === "escape") {
          flushSync(() => {
            setFilterField(null);
            setFilterBuffer("");
          });
          return;
        }
        if (name === "return" || name === "enter") {
          const f = filterFieldRef.current!;
          flushSync(() => {
            setFilters((cur) => ({ ...cur, [f]: filterBufferRef.current }));
            setFilterField(null);
            setFilterBuffer("");
            setCursor((s) => ({ ...s, events: 0 }));
            setScroll((s) => ({ ...s, events: 0 }));
          });
          return;
        }
        if (name === "tab") {
          // Save the current buffer into the active field, then hop to
          // the next field with that field's existing value preloaded.
          const cur = filterFieldRef.current!;
          const idx = FILTER_FIELDS.indexOf(cur);
          const nextField = FILTER_FIELDS[(idx + 1) % FILTER_FIELDS.length]!;
          flushSync(() => {
            setFilters((c) => ({ ...c, [cur]: filterBufferRef.current }));
            setFilterField(nextField);
            setFilterBuffer(filtersRef.current[nextField] ?? "");
          });
          return;
        }
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
            setFilterBuffer(filtersRef.current.source);
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

  // The detail modal needs the actual entry — pull it from the buffer.
  const detailEntry =
    detailSeq === null ? null : events.find((e) => e.seq === detailSeq) || null;

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
        ) : tab === "stats" ? (
          <StatsPane data={insights} window={statsWindow} />
        ) : tab === "events" ? (
          <EventsPane
            entries={filteredEvents()}
            cursor={cursor.events}
            scroll={scroll.events}
            sseStatus={sseStatus}
            filters={filters}
            filterField={filterField}
            filterBuffer={filterBuffer}
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
  cursor: number;
  scroll: number;
  sseStatus: "connecting" | "open" | "closed";
  filters: Filters;
  filterField: FilterField | null;
  filterBuffer: string;
}

function EventsPane({
  entries,
  cursor,
  scroll,
  sseStatus,
  filters,
  filterField,
  filterBuffer,
}: EventsPaneProps): React.ReactNode {
  const visible = entries.slice(scroll, scroll + VISIBLE_ROWS);
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
          // Anchoring time at the left matches log-scanning convention
          // and gives the eye a stable column to track. Verdict comes
          // next, bold + uppercase, since it's the highest-signal field.
          // toolu_id strips its constant "toolu_" prefix — every
          // claude-code event carries it, it's pure noise.
          const idShort = e.tool_use_id.startsWith("toolu_")
            ? e.tool_use_id.slice(6)
            : e.tool_use_id;
          return (
            <box key={e.seq} flexDirection="row">
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
    const value = editing ? `${buffer}_` : filters[label] || "—";
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
    </box>
  );
}

function verdictColor(v?: string, monitor?: boolean): string {
  if (monitor) return "#F5A623";
  if (v === "allow") return "#00FF88";
  if (v === "deny") return "#FF4455";
  return "#888888";
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
              {truncate(g.tool || g.tool_prefix || "*", 18).padEnd(20, " ")}
            </text>
            <text fg="#555555">
              {g.any_command_regex && g.any_command_regex.length > 0
                ? `regex×${g.any_command_regex.length}`
                : (g.evaluators ?? []).join(",")}
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

// ---------- detail modal ---------------------------------------------------

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
      <text fg="#555555">  H toggle full hashes   esc/enter close</text>
    </box>
  );
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
    events: "enter detail  f filter  c clear  i toggle internal  H toggle hashes",
    sessions: "i toggle internal harnesses",
    gates: "a add  e edit  space toggle  M cycle-mode  x x delete",
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
