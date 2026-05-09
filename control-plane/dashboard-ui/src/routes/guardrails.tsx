import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  listGuardrailCatalog,
  listGuardrailEnabled,
  listGuardrailProviders,
  saveGuardrailEnabled,
} from "@/lib/api";
import type {
  GuardrailCatalogEntry,
  GuardrailCatalogProviderError,
  GuardrailEnabledEntry,
  GuardrailProviderView,
} from "@/lib/types";

function GuardrailsTab() {
  const [providers, setProviders] = useState<GuardrailProviderView[]>([]);
  const [catalog, setCatalog] = useState<GuardrailCatalogEntry[]>([]);
  const [providerErrors, setProviderErrors] = useState<GuardrailCatalogProviderError[]>([]);
  const [enabled, setEnabled] = useState<GuardrailEnabledEntry[]>([]);
  const [error, setError] = useState<string>("");
  const saveRequestRef = useRef(0);

  async function refresh() {
    setError("");
    setProviderErrors([]);
    const [providerRes, catalogRes, enabledRes] = await Promise.all([
      listGuardrailProviders(),
      listGuardrailCatalog(),
      listGuardrailEnabled(),
    ]);
    setProviders(providerRes.providers);
    setCatalog(catalogRes.entries);
    setProviderErrors(catalogRes.provider_errors ?? []);
    setEnabled(enabledRes.entries);
  }

  useEffect(() => {
    refresh().catch((err) => setError((err as Error).message));
  }, []);

  const enabledKeys = useMemo(
    () => new Set(enabled.map((entry) => `${entry.provider_id}/${entry.entry_id}`)),
    [enabled],
  );

  async function toggleEntry(entry: GuardrailCatalogEntry, checked: boolean) {
    const key = `${entry.provider_id}/${entry.entry_id}`;
    const prev = enabled;
    const requestID = saveRequestRef.current + 1;
    saveRequestRef.current = requestID;
    const next = checked
      ? [...enabled, { provider_id: entry.provider_id, entry_id: entry.entry_id }]
      : enabled.filter((item) => `${item.provider_id}/${item.entry_id}` !== key);
    setEnabled(next);
    try {
      const saved = await saveGuardrailEnabled(next);
      if (saveRequestRef.current === requestID) {
        setEnabled(saved.entries);
      }
    } catch (err) {
      if (saveRequestRef.current === requestID) {
        setEnabled(prev);
      }
      setError((err as Error).message);
    }
  }

  function providerNote(provider: GuardrailProviderView): string {
    if (provider.id === "nvidia") {
      return "Runtime classifier entries can block after local rules allow.";
    }
    if (provider.id === "openrouter") {
      return "Catalog visibility only in this slice. OpenRouter entries do not run as runtime classifiers yet.";
    }
    return "Provider-specific behavior depends on runtime enforcement support.";
  }

  return (
    <div className="space-y-4">
      <section className="oal-panel">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-neutral-100">External Guardrails</div>
            <div className="text-xs text-muted">Providers are opt-in and run after local rules allow.</div>
          </div>
          <button type="button" className="oal-btn" onClick={() => refresh()}>
            refresh
          </button>
        </div>
        {error && <div className="mb-3 text-xs text-deny">{error}</div>}
        {providerErrors.length > 0 && (
          <div className="mb-3 rounded border border-amber-600/40 bg-amber-950/20 p-3 text-xs text-amber-200">
            {providerErrors.map((item) => (
              <div key={item.provider_id}>
                {item.provider_id}: {item.detail}
              </div>
            ))}
          </div>
        )}
        <div className="grid gap-3 md:grid-cols-2">
          {providers.map((provider) => (
            <div key={provider.id} className="rounded border border-border bg-black/15 p-3">
              <div className="mb-2 flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-semibold">{provider.name}</div>
                  <div className="text-[11px] text-muted">{provider.capabilities.join(" / ")}</div>
                </div>
                <span className="oal-chip">{provider.configured ? "configured" : "not configured"}</span>
              </div>
              <div className="text-[11px] text-muted">
                Configure keys when starting the control plane. Example:{" "}
                <span className="font-mono">
                  {provider.id === "nvidia" ? "NVIDIA_API_KEY" : "OPENROUTER_API_KEY"}
                  =...
                </span>
              </div>
              <div className="mt-2 text-[11px] text-muted">{providerNote(provider)}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="oal-panel">
        <div className="mb-3 text-sm font-semibold text-neutral-100">Catalog</div>
        <div className="overflow-x-auto">
          <table className="oal-table">
            <thead>
              <tr>
                <th>enabled</th>
                <th>provider</th>
                <th>entry</th>
                <th>kind</th>
                <th>runtime</th>
              </tr>
            </thead>
            <tbody>
              {catalog.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-4 text-center text-muted">
                    no catalog entries
                  </td>
                </tr>
              ) : (
                catalog.map((entry) => {
                  const key = `${entry.provider_id}/${entry.entry_id}`;
                  return (
                    <tr key={key}>
                      <td>
                        <input
                          type="checkbox"
                          disabled={!entry.supports_runtime_enforcement}
                          checked={enabledKeys.has(key)}
                          onChange={(e) => toggleEntry(entry, e.target.checked)}
                          aria-label={`enable ${entry.name || entry.entry_id}`}
                        />
                      </td>
                      <td>
                        <span className="oal-chip">{entry.provider_id}</span>
                      </td>
                      <td className="font-mono">{entry.name || entry.entry_id}</td>
                      <td>{entry.kind === "classifier_model" ? "classifier" : "policy"}</td>
                      <td>{entry.supports_runtime_enforcement ? "yes" : "no"}</td>
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

export const Route = createFileRoute("/guardrails")({
  component: GuardrailsTab,
});
