import { useEffect, useRef, useState } from "react";
import { apiBase } from "@/lib/api";
import type { LedgerEntry } from "@/lib/types";

export type SSEStatus = "connecting" | "connected" | "reconnecting";

export function useSSELedger(cap = 5000): { entries: LedgerEntry[]; status: SSEStatus } {
  const [entries, setEntries] = useState<LedgerEntry[]>([]);
  const [status, setStatus] = useState<SSEStatus>("connecting");
  const reconnectRef = useRef<number | null>(null);
  const sseRef = useRef<EventSource | null>(null);

  useEffect(() => {
    let cancelled = false;

    const connect = () => {
      if (cancelled) return;
      setStatus((s) => (s === "connected" ? "reconnecting" : s));
      const es = new EventSource(`${apiBase()}/v1/ledger/tail`);
      sseRef.current = es;

      es.onopen = () => {
        if (cancelled) return;
        setStatus("connected");
      };

      es.onmessage = (ev) => {
        if (cancelled) return;
        try {
          const parsed = JSON.parse(ev.data) as LedgerEntry;
          setEntries((prev) => {
            const next = [...prev, parsed];
            if (next.length > cap) next.splice(0, next.length - cap);
            return next;
          });
        } catch {
          // ignore malformed event
        }
      };

      es.onerror = () => {
        if (cancelled) return;
        setStatus("reconnecting");
        try {
          es.close();
        } catch {
          // ignore
        }
        if (reconnectRef.current !== null) return;
        reconnectRef.current = window.setTimeout(() => {
          reconnectRef.current = null;
          connect();
        }, 2000);
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectRef.current !== null) {
        window.clearTimeout(reconnectRef.current);
        reconnectRef.current = null;
      }
      if (sseRef.current) {
        try {
          sseRef.current.close();
        } catch {
          // ignore
        }
        sseRef.current = null;
      }
    };
  }, [cap]);

  return { entries, status };
}
