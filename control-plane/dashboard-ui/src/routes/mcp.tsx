import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMCPPins } from "@/hooks/usePoll";
import { apiSend } from "@/lib/api";
import { shortHash } from "@/lib/filters";
import { fullLocal, shortTime } from "@/lib/time";
import type { PendingMCPPinRow } from "@/lib/types";

function MCPTab() {
  const { data, error, refresh } = useMCPPins(true);
  const pins = data?.pins ?? [];
  const pending = data?.pending ?? [];
  const [acting, setActing] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selected, setSelected] = useState<PendingMCPPinRow | null>(null);

  const act = async (row: PendingMCPPinRow, action: "accept" | "refuse") => {
    setActing(`${action}:${row.id}`);
    setActionError(null);
    try {
      await apiSend(`/v1/mcp/pin/${action}`, "POST", {
        server: row.server,
        fingerprint: row.fingerprint,
      });
      await refresh();
      setSelected(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="space-y-4">
      <section className="oal-panel">
        <div className="flex items-center gap-3 mb-3">
          <div className="text-[11px] uppercase tracking-wider text-muted">Pending MCP pins</div>
          <div className="text-[11px] text-muted font-mono ml-2">{pending.length} pending</div>
        </div>

        {(error || actionError) && (
          <div className="text-xs text-deny mb-2">{actionError ?? error}</div>
        )}

        <div className="overflow-x-auto">
          <table className="oal-table">
            <thead>
              <tr>
                <th>server</th>
                <th>status</th>
                <th>fingerprint</th>
                <th>seen</th>
                <th>actions</th>
              </tr>
            </thead>
            <tbody>
              {pending.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center text-muted py-4">
                    no pending MCP pins
                  </td>
                </tr>
              ) : (
                pending.map((row) => (
                  <tr key={row.id}>
                    <td className="font-mono">{row.server}</td>
                    <td>
                      <span className="oal-chip">{row.status}</span>
                    </td>
                    <td className="font-mono text-muted" title={row.fingerprint}>
                      {shortHash(row.fingerprint, 24)}
                      {row.known_fingerprint && (
                        <span className="block text-[10px]" title={row.known_fingerprint}>
                          was {shortHash(row.known_fingerprint, 18)}
                        </span>
                      )}
                    </td>
                    <td className="font-mono" title={fullLocal(row.updated_at)}>
                      {shortTime(row.updated_at)}
                    </td>
                    <td>
                      <div className="flex gap-2">
                        <button
                          className="oal-btn text-xs"
                          disabled={acting !== null}
                          onClick={() => void act(row, "accept")}
                        >
                          {acting === `accept:${row.id}` ? "Accepting" : "Accept"}
                        </button>
                        <button className="oal-btn text-xs" onClick={() => setSelected(row)}>
                          Details
                        </button>
                        <button
                          className="oal-btn text-xs"
                          disabled={acting !== null}
                          onClick={() => void act(row, "refuse")}
                        >
                          {acting === `refuse:${row.id}` ? "Refusing" : "Refuse"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-xl rounded-md border border-border bg-panel p-4 shadow-xl">
            <div className="flex items-center justify-between gap-3 border-b border-border pb-3">
              <div>
                <div className="text-[11px] uppercase tracking-wider text-muted">
                  MCP pin request
                </div>
                <div className="font-mono text-sm">{selected.server}</div>
              </div>
              <button className="oal-btn-link" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
            <div className="mt-3 space-y-3 text-xs">
              <div>
                <div className="text-muted">fingerprint</div>
                <div className="font-mono break-all">{selected.fingerprint}</div>
              </div>
              {selected.known_fingerprint && (
                <div>
                  <div className="text-muted">known fingerprint</div>
                  <div className="font-mono break-all">{selected.known_fingerprint}</div>
                </div>
              )}
              <div>
                <div className="text-muted">server info</div>
                <pre className="mt-1 max-h-56 overflow-auto rounded border border-border bg-bg p-2 font-mono text-[11px]">
                  {JSON.stringify(selected.server_info ?? {}, null, 2)}
                </pre>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button className="oal-btn" onClick={() => void act(selected, "accept")}>
                  Accept
                </button>
                <button className="oal-btn" onClick={() => void act(selected, "refuse")}>
                  Refuse
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <section className="oal-panel">
        <div className="flex items-center gap-3 mb-3">
          <div className="text-[11px] uppercase tracking-wider text-muted">MCP pins</div>
          <div className="text-[11px] text-muted font-mono ml-2">{pins.length} pinned</div>
        </div>

        {error && <div className="text-xs text-deny mb-2">{error}</div>}

        <div className="overflow-x-auto">
          <table className="oal-table">
            <thead>
              <tr>
                <th>server</th>
                <th>fingerprint</th>
              </tr>
            </thead>
            <tbody>
              {pins.length === 0 ? (
                <tr>
                  <td colSpan={2} className="text-center text-muted py-4">
                    no MCP pins
                  </td>
                </tr>
              ) : (
                pins.map((pin) => (
                  <tr key={pin.server}>
                    <td className="font-mono">{pin.server}</td>
                    <td className="font-mono text-muted" title={pin.fingerprint}>
                      {shortHash(pin.fingerprint, 24)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export const Route = createFileRoute("/mcp")({
  component: MCPTab,
});
