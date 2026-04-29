import type { ModeInfo } from "@/lib/types";

interface HeaderProps {
  apiBase: string;
  mode: ModeInfo | null;
}

export function Header({ apiBase, mode }: HeaderProps) {
  const modeLabel = mode?.mode?.toUpperCase() ?? "";
  let badgeClass = "bg-chip text-muted";
  if (modeLabel === "FIREWALL") badgeClass = "bg-deny/20 text-deny";
  else if (modeLabel === "MONITOR") badgeClass = "bg-monitor/20 text-monitor";

  return (
    <header className="flex items-center gap-3 px-5 py-3 border-b border-border bg-panel">
      <h1 className="text-sm font-semibold tracking-wide text-neutral-100 m-0">
        OpenAgentLock
      </h1>
      <span className="font-mono text-[11px] text-muted">{apiBase || "(dev proxy)"}</span>
      <span
        className={`ml-auto inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${badgeClass}`}
        title="Monitor records every call and allows. Firewall enforces deny rules."
      >
        {modeLabel || "—"}
      </span>
    </header>
  );
}
