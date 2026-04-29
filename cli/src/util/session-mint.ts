// Shared helper for minting an *attested* session against a control
// plane. Used by `agentlock session create` and by `agentlock install`
// when invoked with `--tier software|totp` so the install/uninstall
// flow runs under a real signed session instead of forcing the daemon
// into AGENTLOCK_ALLOW_UNATTESTED.
//
// Layout mirrors what `runSessionCreate` used to do inline:
//   1. Load (or create) the long-lived signer for the requested tier.
//   2. Generate / reuse the session keypair under $AGENTLOCK_HOME.
//   3. Canonicalize + sign the attestation.
//   4. POST /v1/sessions/create.
//
// On success the on-disk `session-current.key` is what subsequent calls
// (gates, ledger appends) sign with — which is why it's persisted.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import * as ed25519 from "@noble/ed25519";

import { apiClient, type SessionResponse, type SessionStartRequest } from "./api";
import { agentlockHome } from "./paths";
import { loadOrCreateSoftwareSigner } from "../signer/software";
import { loadTOTPSigner } from "../signer/totp";
import { canonicalAttestation } from "../signer/canonical";
import type { Signer, SignerKind } from "../signer/types";

export type AttestedTier = "software" | "totp";

export interface MintAttestedOptions {
  tier: AttestedTier;
  url?: string;
  policyHash?: string;
  // tier=totp only:
  code?: string;
  passphrase?: string;
}

export async function mintAttestedSession(
  opts: MintAttestedOptions,
): Promise<SessionResponse> {
  const home = agentlockHome();
  mkdirSync(home, { recursive: true });

  let signer: Signer;
  let signerKind: SignerKind;
  if (opts.tier === "software") {
    signer = await loadOrCreateSoftwareSigner(home);
    signerKind = "software";
  } else {
    if (!opts.code || !opts.passphrase) {
      throw new Error(
        "--tier totp requires --code <6-digit> and --passphrase <pp>. " +
          "Run `agentlock signer enroll --tier totp --passphrase <pp>` first.",
      );
    }
    signer = await loadTOTPSigner(home, { code: opts.code, passphrase: opts.passphrase });
    signerKind = "totp_backed_software";
  }

  const sessionKeyPath = join(home, "session-current.key");
  let sessionSeed: Uint8Array;
  if (existsSync(sessionKeyPath)) {
    sessionSeed = new Uint8Array(readFileSync(sessionKeyPath));
  } else {
    sessionSeed = new Uint8Array(32);
    crypto.getRandomValues(sessionSeed);
    writeFileSync(sessionKeyPath, sessionSeed, { mode: 0o600 });
  }
  const sessionPub = await ed25519.getPublicKeyAsync(sessionSeed);

  const policyHash = opts.policyHash ?? readPolicyHash(home) ?? "sha256:0000";
  const payload = {
    policy_hash: policyHash,
    session_pubkey: `ed25519:${toHex(sessionPub)}`,
    signer: signerKind,
    signer_pubkey: `ed25519:${toHex(signer.publicKey)}`,
  };
  const canon = new TextEncoder().encode(canonicalAttestation(payload));
  const attestation = await signer.sign(canon);

  const req: SessionStartRequest = {
    policy_hash: payload.policy_hash,
    session_pubkey: payload.session_pubkey,
    signer: payload.signer,
    signer_pubkey: payload.signer_pubkey,
    attestation: `ed25519:${toHex(attestation)}`,
  };

  const client = apiClient(opts.url);
  return client.createSession(req);
}

function readPolicyHash(home: string): string | null {
  const p = join(home, "policy.hash");
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8").trim();
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");
}
