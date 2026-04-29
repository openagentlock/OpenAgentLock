// Dashboard API client. In dev the Vite dev server proxies /v1/* to the
// daemon on :7878; in prod (embedded in the Go binary) we're served from
// :7879 and cross-origin to :7878 with the daemon's loopback-CORS
// whitelist. Override the base via `localStorage.setItem("oalApi", "...")`.

export function apiBase(): string {
  try {
    const override =
      typeof localStorage !== "undefined" ? localStorage.getItem("oalApi") : null;
    if (override && override.length > 0) return override;
  } catch {
    // localStorage inaccessible (SSR, privacy mode, iframe). Ignore.
  }
  if (import.meta.env.DEV) return "";
  return "http://127.0.0.1:7878";
}

// mergeHeaders normalizes whatever shape the caller passed (undefined /
// plain object / Headers instance / tuple array) into a plain record so
// we can merge in our default Accept header without silently dropping
// the caller's fields — which `{...init?.headers}` does when headers is
// a Headers instance.
function mergeHeaders(extra: HeadersInit | undefined): Record<string, string> {
  const base: Record<string, string> = { Accept: "application/json" };
  if (!extra) return base;
  if (extra instanceof Headers) {
    extra.forEach((v, k) => {
      base[k] = v;
    });
    return base;
  }
  if (Array.isArray(extra)) {
    for (const [k, v] of extra) base[k] = v;
    return base;
  }
  return { ...base, ...extra };
}

export async function apiJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, {
    ...init,
    headers: mergeHeaders(init?.headers),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const hint = body ? ` — ${body.slice(0, 200)}` : "";
    throw new Error(`HTTP ${res.status} ${res.statusText}${hint}`);
  }
  return (await res.json()) as T;
}

export async function apiSend<T>(
  path: string,
  method: "POST" | "PATCH" | "DELETE",
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    const hint = errBody ? ` — ${errBody.slice(0, 200)}` : "";
    throw new Error(`HTTP ${res.status} ${res.statusText}${hint}`);
  }
  const text = await res.text();
  if (!text || text.trim().length === 0) return {} as T;
  // If we got bytes back, the server promised JSON. Propagate parse
  // failures so callers see malformed responses instead of getting a
  // silent empty object that looks successful.
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new Error(
      `malformed JSON response: ${(err as Error).message}; body=${text.slice(0, 200)}`,
    );
  }
}
