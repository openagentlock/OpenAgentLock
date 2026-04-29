// OpenAgentLock dashboard TUI. Keyboard-driven read-mostly viewer over
// the same JSON endpoints the web dashboard talks to.
//
// Tabs:  Events | Sessions | Rules | Mode
//   h/l or ←/→     switch tab
//   j/k or ↑/↓     scroll within the focused tab
//   m              flip daemon mode (firewall ↔ monitor)
//   r              force-refresh the focused tab
//   q or esc       quit
//
// The daemon base URL comes from the ApiClient passed in (so tests can
// point at a Bun.serve() mock and the real CLI points at 127.0.0.1:7878).

import { createCliRenderer, type KeyEvent } from "@opentui/core";
import { createRoot, flushSync, useRenderer } from "@opentui/react";
import { useEffect, useRef, useState } from "react";
import type {
  ApiClient,
  ModeResponse,
  PolicyGateView,
  PolicyViewResponse,
  SessionsListResponse,
  SessionSummary,
} from "../util/api.ts";

// ---------- shared types ---------------------------------------------------

interface LedgerEntry {
  seq: number;
  ts: string;
  source: string;
  tool_use_id: string;
  signer: string;
  rule_id?: string;
  verdict?: string;
}

type TabName = "events" | "sessions" | "rules" | "mode";

const TABS: { name: string; description: string; value: TabName }[] = [
  { name: "Events", description: "Live ledger tail", value: "events" },
  { name: "Sessions", description: "Who's connected", value: "sessions" },
  { name: "Rules", description: "Loaded policy gates", value: "rules" },
  { name: "Mode", description: "Firewall / monitor", value: "mode" },
];

interface DashboardProps {
  api: ApiClient;
  onQuit: () => void;
}

// useInterval stashes the latest callback in a ref so the interval's
// lifecycle is tied only to `ms`. Inline callbacks change identity on
// every render, which would otherwise churn setInterval and cause each
// tick to fire on the wrong schedule or not at all.
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
  const [tab, setTab] = useState<TabName>("events");
  const [scroll, setScroll] = useState<Record<TabName, number>>({
    events: 0,
    sessions: 0,
    rules: 0,
    mode: 0,
  });
  const [daemonOk, setDaemonOk] = useState<boolean | null>(null);
  const [mode, setMode] = useState<ModeResponse | null>(null);
  const [sessions, setSessions] = useState<SessionsListResponse | null>(null);
  const [policy, setPolicy] = useState<PolicyViewResponse | null>(null);
  const [events, setEvents] = useState<LedgerEntry[]>([]);
  const [sseStatus, setSseStatus] = useState<"connecting" | "open" | "closed">(
    "connecting",
  );
  const [toast, setToast] = useState<string>("");

  // --- polling ---
  useInterval(() => {
    api
      .health()
      .then(() => setDaemonOk(true))
      .catch(() => setDaemonOk(false));
    api.getMode().then(setMode).catch(() => {});
    api.listSessions().then(setSessions).catch(() => {});
    api.policyView().then(setPolicy).catch(() => {});
  }, 2000);

  // --- SSE ledger tail ---
  useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    function connect(): void {
      if (cancelled) return;
      setSseStatus("connecting");
      try {
        es = new EventSource(api.ledgerTailUrl());
      } catch {
        setSseStatus("closed");
        setTimeout(connect, 2000);
        return;
      }
      es.onopen = () => setSseStatus("open");
      es.onmessage = (ev) => {
        try {
          const entry = JSON.parse(ev.data) as LedgerEntry;
          setEvents((prev) => {
            const next = [entry, ...prev].slice(0, 500);
            return next;
          });
        } catch {
          // non-JSON keepalive; ignore.
        }
      };
      es.onerror = () => {
        setSseStatus("closed");
        if (es) es.close();
        setTimeout(connect, 2000);
      };
    }
    connect();
    return () => {
      cancelled = true;
      if (es) es.close();
    };
  }, [api]);

  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function flashToast(msg: string): void {
    setToast(msg);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(""), 2500);
  }
  useEffect(() => {
    // Clear the pending toast timer on unmount so it doesn't call
    // setState on a detached component when the user quits.
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current);
    };
  }, []);

  // --- keyboard ---
  // Direct subscription to renderer.keyInput (instead of useKeyboard)
  // because the useEffectEvent-wrapped hook has shown a stale-handler
  // issue on some opentui + React 19 combos; arrow / j / k keys never
  // fired through the hook. This pattern reads state via refs so the
  // handler can be installed once and always see the latest values.
  const tabRef = useRef(tab);
  tabRef.current = tab;
  const modeRef = useRef(mode);
  modeRef.current = mode;
  const renderer = useRenderer();
  useEffect(() => {
    const kh = renderer.keyInput;
    if (!kh) return;
    // stdin raw-data callbacks aren't React synthetic events, so the
    // opentui reconciler doesn't auto-flush state updates from here —
    // wrap each setState in flushSync so the UI repaints immediately.
    const handler = (e: KeyEvent): void => {
      const name = e.name;
      if (name === "q" || name === "escape") return onQuit();
      if (name === "left" || name === "h") {
        const idx = TABS.findIndex((t) => t.value === tabRef.current);
        const next = TABS[(idx - 1 + TABS.length) % TABS.length];
        if (next) flushSync(() => setTab(next.value));
        return;
      }
      if (name === "right" || name === "l") {
        const idx = TABS.findIndex((t) => t.value === tabRef.current);
        const next = TABS[(idx + 1) % TABS.length];
        if (next) flushSync(() => setTab(next.value));
        return;
      }
      if (name === "down" || name === "j") {
        flushSync(() => setScroll((s) => {
          const t = tabRef.current;
          return { ...s, [t]: s[t] + 1 };
        }));
        return;
      }
      if (name === "up" || name === "k") {
        flushSync(() => setScroll((s) => {
          const t = tabRef.current;
          return { ...s, [t]: Math.max(0, s[t] - 1) };
        }));
        return;
      }
      if (name === "r") {
        api.getMode().then((r) => flushSync(() => setMode(r))).catch(() => {});
        api.listSessions().then((r) => flushSync(() => setSessions(r))).catch(() => {});
        api.policyView().then((r) => flushSync(() => setPolicy(r))).catch(() => {});
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
        api
          .patchMode(next)
          .then((r) => {
            flushSync(() => setMode(r));
            flashToast(`mode → ${r.mode}`);
          })
          .catch((err) => flashToast(`mode flip failed: ${err.message}`));
        return;
      }
    };
    kh.on("keypress", handler);
    return () => {
      kh.off("keypress", handler);
    };
  }, [renderer, api]);

  return (
    <box flexDirection="column" padding={1}>
      <Header daemonUrl={api.baseUrl} daemonOk={daemonOk} mode={mode} />
      <TabBar active={tab} />
      <box flexDirection="column" flexGrow={1} marginTop={1}>
        {tab === "events" ? (
          <EventsPane entries={events} scroll={scroll.events} sseStatus={sseStatus} />
        ) : tab === "sessions" ? (
          <SessionsPane data={sessions} scroll={scroll.sessions} />
        ) : tab === "rules" ? (
          <RulesPane data={policy} scroll={scroll.rules} />
        ) : (
          <ModePane data={mode} />
        )}
      </box>
      <Footer toast={toast} />
    </box>
  );
}

// ---------- header ---------------------------------------------------------

interface HeaderProps {
  daemonUrl: string;
  daemonOk: boolean | null;
  mode: ModeResponse | null;
}

function Header({ daemonUrl, daemonOk, mode }: HeaderProps): React.ReactNode {
  const dot = daemonOk === null ? "?" : daemonOk ? "●" : "○";
  const dotColor = daemonOk === null ? "#888888" : daemonOk ? "#00FF88" : "#FF4455";
  const modeColor = mode?.mode === "monitor" ? "#F5A623" : "#00FF88";
  const modeLabel = mode ? mode.mode.toUpperCase() : "—";
  return (
    <box flexDirection="column" marginBottom={1}>
      {/* Brand ASCII font. The `slick` font fits 80-col terminals. */}
      <ascii-font text="OPENAGENTLOCK" font="slick" color="#7FE7DC" />
      <box flexDirection="row" marginTop={0}>
        <text fg="#888888">local-first hardening for AI coding agents  </text>
        <text fg={dotColor}>{dot} </text>
        <text fg="#CCCCCC">{daemonUrl}  </text>
        <text fg="#555555">|  mode: </text>
        <text fg={modeColor} attributes={1}>
          {modeLabel}
        </text>
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

// ---------- events pane ----------------------------------------------------

interface EventsPaneProps {
  entries: LedgerEntry[];
  scroll: number;
  sseStatus: "connecting" | "open" | "closed";
}

function EventsPane({ entries, scroll, sseStatus }: EventsPaneProps): React.ReactNode {
  const visible = entries.slice(scroll, scroll + 20);
  const statusColor =
    sseStatus === "open" ? "#00FF88" : sseStatus === "closed" ? "#FF4455" : "#F5A623";
  return (
    <box flexDirection="column">
      <box flexDirection="row" marginBottom={1}>
        <text fg={statusColor}>● SSE: {sseStatus}</text>
        <text fg="#555555">    {entries.length} entries buffered (seq DESC)</text>
      </box>
      {entries.length === 0 ? (
        <text fg="#666666">
          no events yet. waiting for the daemon's Merkle ledger to append one.
        </text>
      ) : (
        visible.map((e) => (
          <box key={e.seq} flexDirection="row">
            <text fg="#555555">{String(e.seq).padStart(4, " ")}  </text>
            <text fg={verdictColor(e.verdict)}>
              {(e.verdict ?? "—").padEnd(5, " ")}
            </text>
            <text fg="#AAAAAA">  {e.source.padEnd(13, " ")}</text>
            <text fg="#CCCCCC">  {e.rule_id || "—"}</text>
            <text fg="#555555">    {truncate(e.tool_use_id, 28)}</text>
            <text fg="#444444">    {formatTs(e.ts)}</text>
          </box>
        ))
      )}
    </box>
  );
}

function verdictColor(v?: string): string {
  if (v === "allow") return "#00FF88";
  if (v === "deny") return "#FF4455";
  return "#888888";
}

// ---------- sessions pane --------------------------------------------------

function SessionsPane({
  data,
  scroll,
}: {
  data: SessionsListResponse | null;
  scroll: number;
}): React.ReactNode {
  if (!data) {
    return <text fg="#888888">loading sessions...</text>;
  }
  if (data.sessions.length === 0) {
    return <text fg="#888888">no sessions recorded yet.</text>;
  }
  const rows: SessionSummary[] = data.sessions.slice(scroll, scroll + 18);
  return (
    <box flexDirection="column">
      <box flexDirection="row" marginBottom={1}>
        <text fg="#888888">live policy hash: </text>
        <text fg="#CCCCCC">{data.live_policy_hash}</text>
      </box>
      <box flexDirection="row" marginBottom={1}>
        <text fg="#555555" attributes={1}>
          {"  ID".padEnd(24, " ")}
          {"HARNESS".padEnd(14, " ")}
          {"SIGNER".padEnd(16, " ")}
          {"ACTIVE".padEnd(8, " ")}
          {"NEEDS_RELOAD"}
        </text>
      </box>
      {rows.map((s) => (
        <box key={s.id} flexDirection="row">
          <text fg="#CCCCCC">{("  " + truncate(s.id, 22)).padEnd(24, " ")}</text>
          <text fg="#AAAAAA">{s.harness.padEnd(14, " ")}</text>
          <text fg={signerColor(s.signer)}>{s.signer.padEnd(16, " ")}</text>
          <text fg={s.active ? "#00FF88" : "#888888"}>
            {(s.active ? "yes" : "ended").padEnd(8, " ")}
          </text>
          <text fg={s.needs_reload ? "#F5A623" : "#666666"}>
            {s.needs_reload ? "yes" : "no"}
          </text>
        </box>
      ))}
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

// ---------- rules pane -----------------------------------------------------

function RulesPane({
  data,
  scroll,
}: {
  data: PolicyViewResponse | null;
  scroll: number;
}): React.ReactNode {
  if (!data) {
    return <text fg="#888888">loading policy...</text>;
  }
  const rows: PolicyGateView[] = data.gates.slice(scroll, scroll + 18);
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
      {rows.map((g) => (
        <box key={g.id} flexDirection="row">
          <text fg={g.disabled ? "#555555" : "#CCCCCC"}>
            {(g.disabled ? "  -" : "  •") + " " + g.id.padEnd(36, " ")}
          </text>
          <text fg="#888888">{(g.mode || "—").padEnd(10, " ")}</text>
          <text fg="#888888">
            {truncate(g.tool || g.tool_prefix || "*", 18).padEnd(20, " ")}
          </text>
          <text fg="#555555">
            {g.any_command_regex && g.any_command_regex.length > 0
              ? `regex×${g.any_command_regex.length}`
              : (g.evaluators ?? []).join(",")}
          </text>
        </box>
      ))}
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
        <text fg="#7FE7DC" attributes={1}>
          m
        </text>
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

// ---------- footer ---------------------------------------------------------

function Footer({ toast }: { toast: string }): React.ReactNode {
  return (
    <box flexDirection="column" marginTop={1}>
      {toast ? (
        <text fg="#7FE7DC">{toast}</text>
      ) : (
        <text fg="#555555">
          h/l tab  j/k scroll  m flip mode  r refresh  q quit
        </text>
      )}
    </box>
  );
}

// ---------- utilities ------------------------------------------------------

function truncate(s: string, n: number): string {
  if (!s) return "";
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

function formatTs(ts: string): string {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    // HH:MM:SS in the local TZ — dense enough for a terminal row.
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return ts;
  }
}

// ---------- entrypoint -----------------------------------------------------

export async function runDashboardTUI(api: ApiClient): Promise<void> {
  const renderer = await createCliRenderer({ exitOnCtrlC: true });
  // Explicit start: without it the render loop stays in "idle" and
  // keypress events don't reach the React tree in real-terminal runs.
  // `start()` is idempotent and cheap.
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
