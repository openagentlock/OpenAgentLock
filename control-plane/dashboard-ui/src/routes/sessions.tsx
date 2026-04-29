import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useSessions } from "@/hooks/usePoll";
import { INTERNAL_HARNESSES, shortHash } from "@/lib/filters";
import { fullLocal, shortTime } from "@/lib/time";

function SessionsTab() {
  const { data, error } = useSessions(true);
  const [showInternal, setShowInternal] = useState(false);

  const rows = useMemo(() => {
    const sessions = data?.sessions ?? [];
    return sessions.filter((s) => {
      if (!showInternal && INTERNAL_HARNESSES.has(s.harness)) return false;
      return true;
    });
  }, [data, showInternal]);

  return (
    <div className="space-y-4">
      <section className="oal-panel">
        <div className="flex items-center gap-3 mb-3">
          <div className="text-[11px] uppercase tracking-wider text-muted">Sessions</div>
          <div className="text-[11px] text-muted font-mono ml-2">
            live policy_hash={shortHash(data?.live_policy_hash, 12) || "—"}
          </div>
          <label className="flex items-center gap-2 text-[11px] text-muted ml-auto">
            <input
              type="checkbox"
              checked={showInternal}
              onChange={(e) => setShowInternal(e.target.checked)}
            />
            show internal
          </label>
        </div>

        {error && <div className="text-xs text-deny mb-2">{error}</div>}

        <div className="overflow-x-auto">
          <table className="oal-table">
            <thead>
              <tr>
                <th>id</th>
                <th>harness</th>
                <th>signer</th>
                <th>policy_hash</th>
                <th>started</th>
                <th>status</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center text-muted py-4">
                    no sessions
                  </td>
                </tr>
              ) : (
                rows.map((s) => {
                  let statusNode: ReactElement;
                  if (!s.active) {
                    statusNode = <span className="oal-chip">ended</span>;
                  } else if (s.needs_reload) {
                    statusNode = (
                      <span className="inline-block px-1.5 py-0.5 rounded text-[11px] bg-monitor/20 text-monitor">
                        needs reload
                      </span>
                    );
                  } else {
                    statusNode = (
                      <span className="inline-block px-1.5 py-0.5 rounded text-[11px] bg-allow/20 text-allow">
                        current
                      </span>
                    );
                  }
                  return (
                    <tr key={s.id}>
                      <td className="font-mono text-muted" title={s.id}>
                        {shortHash(s.id, 12)}
                      </td>
                      <td>
                        <span className="oal-chip">{s.harness || "(none)"}</span>
                      </td>
                      <td className="font-mono">{s.signer}</td>
                      <td className="font-mono text-muted" title={s.policy_hash}>
                        {shortHash(s.policy_hash, 12)}
                      </td>
                      <td className="font-mono" title={fullLocal(s.started_at)}>
                        {shortTime(s.started_at)}
                      </td>
                      <td>{statusNode}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export const Route = createFileRoute("/sessions")({
  component: SessionsTab,
});
