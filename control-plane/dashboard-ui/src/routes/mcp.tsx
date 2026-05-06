import { createFileRoute } from "@tanstack/react-router";
import { useMCPPins } from "@/hooks/usePoll";
import { shortHash } from "@/lib/filters";

function MCPTab() {
  const { data, error } = useMCPPins(true);
  const pins = data?.pins ?? [];

  return (
    <div className="space-y-4">
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
