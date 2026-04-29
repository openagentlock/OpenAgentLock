import type { ModeInfo } from "@/lib/types";

interface ModeToggleProps {
  mode: ModeInfo | null;
  setMode: (m: "monitor" | "firewall" | "") => Promise<void>;
}

export function ModeToggle({ mode, setMode }: ModeToggleProps) {
  const current = mode?.mode;
  const override = mode?.runtime_override ?? "";
  const env = mode?.env ?? "";

  const onClick = async (target: "monitor" | "firewall") => {
    try {
      await setMode(target);
    } catch (e) {
      alert(`Failed to change mode: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const onClear = async () => {
    try {
      await setMode("");
    } catch (e) {
      alert(`Failed to clear override: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <div className="flex items-center gap-3">
      <div className="inline-flex border border-border rounded overflow-hidden bg-chip">
        <button
          type="button"
          onClick={() => onClick("monitor")}
          className={`px-3 py-1 text-xs transition-colors ${
            current === "monitor" ? "bg-monitor text-bg" : "text-muted hover:text-neutral-100"
          }`}
        >
          Monitor
        </button>
        <button
          type="button"
          onClick={() => onClick("firewall")}
          className={`px-3 py-1 text-xs transition-colors ${
            current === "firewall" ? "bg-deny text-white" : "text-muted hover:text-neutral-100"
          }`}
        >
          Firewall
        </button>
      </div>
      <span className="text-[11px] text-muted font-mono">
        env={env || "—"} override={override || "—"}
      </span>
      {override && (
        <button type="button" className="oal-btn-link" onClick={onClear}>
          clear override
        </button>
      )}
    </div>
  );
}
