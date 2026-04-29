import { useCallback, useEffect, useRef, useState } from "react";
import { apiJSON, apiSend } from "@/lib/api";
import type { ModeInfo, PolicyView, RootInfo, SessionsResponse } from "@/lib/types";

export function usePoll(fn: () => void | Promise<void>, intervalMs: number, paused = false): void {
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn;
  }, [fn]);

  useEffect(() => {
    if (paused) return;
    let cancelled = false;
    // Async rejections don't throw synchronously, so a try/catch around
    // the fn call does nothing for promise rejects. Attach .catch()
    // directly to swallow async errors and keep the interval alive.
    const tick = () => {
      if (cancelled) return;
      let result: void | Promise<void>;
      try {
        result = fnRef.current();
      } catch {
        return;
      }
      if (result instanceof Promise) {
        result.catch(() => {
          // keep polling on transient daemon errors (CORS preflight during
          // restart, network blip, etc.). The individual hook records
          // the error in its own state for the UI.
        });
      }
    };
    tick();
    const id = window.setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [intervalMs, paused]);
}

export function useRootInfo(): {
  root: RootInfo | null;
  rootError: string | null;
  refreshRoot: () => Promise<void>;
} {
  const [root, setRoot] = useState<RootInfo | null>(null);
  const [rootError, setRootError] = useState<string | null>(null);

  const refreshRoot = useCallback(async () => {
    try {
      const r = await apiJSON<RootInfo>("/v1/ledger/root");
      setRoot(r);
      setRootError(null);
    } catch (e) {
      setRootError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  usePoll(refreshRoot, 3000);

  return { root, rootError, refreshRoot };
}

export function useModeInfo(): {
  mode: ModeInfo | null;
  refreshMode: () => Promise<void>;
  setMode: (m: "monitor" | "firewall" | "") => Promise<void>;
} {
  const [mode, setModeState] = useState<ModeInfo | null>(null);

  const refreshMode = useCallback(async () => {
    try {
      const m = await apiJSON<ModeInfo>("/v1/mode");
      setModeState(m);
    } catch {
      // ignore
    }
  }, []);

  const setMode = useCallback(
    async (m: "monitor" | "firewall" | "") => {
      await apiSend("/v1/mode", "PATCH", { mode: m });
      await refreshMode();
    },
    [refreshMode],
  );

  usePoll(refreshMode, 4000);

  return { mode, refreshMode, setMode };
}

export function usePolicyView(active: boolean): {
  policy: PolicyView | null;
  error: string | null;
  refresh: () => Promise<void>;
} {
  const [policy, setPolicy] = useState<PolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const p = await apiJSON<PolicyView>("/v1/policy/view");
      setPolicy(p);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  usePoll(refresh, 4000, !active);

  return { policy, error, refresh };
}

export function useSessions(active: boolean): {
  data: SessionsResponse | null;
  error: string | null;
  refresh: () => Promise<void>;
} {
  const [data, setData] = useState<SessionsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await apiJSON<SessionsResponse>("/v1/sessions");
      setData(s);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  usePoll(refresh, 4000, !active);

  return { data, error, refresh };
}
