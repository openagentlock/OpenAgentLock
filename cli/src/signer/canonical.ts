import * as ed25519 from "@noble/ed25519";
import type { AttestationPayload } from "./types";

// Canonical JSON for the attestation payload. Must produce byte-identical
// output on the Go verifier side (see control-plane/internal/signer/verify.go).
// Spec (deliberately minimal for this shape):
// - UTF-8, no whitespace, no trailing newline
// - keys emitted in ascending byte order
// - values are ASCII strings; control chars (< 0x20) are forbidden so we
//   never need to reason about JSON escaping beyond `\\` and `\"`
export function canonicalAttestation(p: AttestationPayload): string {
  const ordered: Array<[string, string]> = [
    ["policy_hash", p.policy_hash],
    ["session_pubkey", p.session_pubkey],
    ["signer", p.signer],
    ["signer_pubkey", p.signer_pubkey],
  ];
  const parts = ordered.map(([k, v]) => {
    assertPrintable(k, v);
    return `"${k}":"${escapeString(v)}"`;
  });
  return `{${parts.join(",")}}`;
}

export async function signAttestation(
  p: AttestationPayload,
  seed: Uint8Array,
): Promise<Uint8Array> {
  const msg = new TextEncoder().encode(canonicalAttestation(p));
  return ed25519.signAsync(msg, seed);
}

function assertPrintable(key: string, value: string): void {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) {
      throw new Error(
        `canonicalAttestation: field ${key} contains control char 0x${c.toString(16)}`,
      );
    }
  }
}

function escapeString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
