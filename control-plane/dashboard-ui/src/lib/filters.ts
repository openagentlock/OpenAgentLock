export const INTERNAL_SOURCES = new Set<string>(["system", "installer", "admin"]);
export const INTERNAL_HARNESSES = new Set<string>(["installer", "system", "admin", "unknown", ""]);

export function isInternalSource(source: string | undefined | null): boolean {
  if (source === undefined || source === null) return true;
  return INTERNAL_SOURCES.has(source);
}

export function isInternalHarness(harness: string | undefined | null): boolean {
  if (harness === undefined || harness === null) return true;
  return INTERNAL_HARNESSES.has(harness);
}

export function shortHash(h: string | undefined | null, max = 12): string {
  if (!h) return "";
  const stripped = h.startsWith("sha256:") ? h.slice("sha256:".length) : h;
  if (stripped.length <= max) return stripped;
  return stripped.slice(0, max);
}
