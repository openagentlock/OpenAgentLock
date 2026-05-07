import { readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import * as ed25519 from "@noble/ed25519";

import { apiClient, type SessionStartRequest } from "../util/api";
import { agentlockHome } from "../util/paths";
import { loadOrCreateSoftwareSigner } from "../signer/software";
import { loadTOTPSigner } from "../signer/totp";
import { loadOSKeychainSigner } from "../signer/keychain";
import { canonicalAttestation } from "../signer/canonical";
import type { Signer, SignerKind } from "../signer/types";

export type SessionTier = "software" | "totp" | "os-keychain";

interface Options {
  tier: SessionTier;
  url?: string;
  json: boolean;
  policyHash?: string;
  code?: string;
  passphrase?: string;
  userId?: string;
  groups?: string[];
}

export async function runSessionEnd(opts: {
  id: string;
  url?: string;
  json: boolean;
}): Promise<void> {
  const client = apiClient(opts.url);
  await client.endSession(opts.id);
  if (opts.json) {
    process.stdout.write(JSON.stringify({ ended: true, id: opts.id }) + "\n");
  } else {
    process.stdout.write(`session ended: ${opts.id}\n`);
  }
}

export async function runSessionRotate(opts: Options & { id: string }): Promise<void> {
  const home = agentlockHome();
  mkdirSync(home, { recursive: true });

  let signer: Signer;
  let signerKind: SignerKind;
  if (opts.tier === "software") {
    signer = await loadOrCreateSoftwareSigner(home);
    signerKind = "software";
  } else if (opts.tier === "os-keychain") {
    signer = await loadOSKeychainSigner(home);
    signerKind = "os_keychain";
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

  // Rotation issues a fresh session key too so compromise of the old
  // in-memory session key does not carry into the new window. Compute
  // the keypair + attestation first; only persist to disk AFTER the
  // daemon accepts so a failed rotate doesn't overwrite the working key.
  const newSeed = new Uint8Array(32);
  crypto.getRandomValues(newSeed);
  const newSessionPub = await ed25519.getPublicKeyAsync(newSeed);

  const policyHash = opts.policyHash ?? readPolicyHash(home) ?? "sha256:0000";
  const payload = {
    policy_hash: policyHash,
    session_pubkey: `ed25519:${toHex(newSessionPub)}`,
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
    user_id: opts.userId,
    groups: opts.groups,
  };

  const client = apiClient(opts.url);
  const res = await client.rotateSession(opts.id, req);
  // Daemon accepted: now it's safe to replace the on-disk session key.
  writeFileSync(join(home, "session-current.key"), newSeed, { mode: 0o600 });
  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  } else {
    process.stdout.write(
      `rotated: ${res.id}\n` +
        `  signer:   ${res.signer}\n` +
        `  expires:  ${res.expires_at}\n`,
    );
  }
}

export async function runSessionCreate(opts: Options): Promise<void> {
  const home = agentlockHome();
  mkdirSync(home, { recursive: true });

  let signer: Signer;
  let signerKind: SignerKind;
  if (opts.tier === "software") {
    signer = await loadOrCreateSoftwareSigner(home);
    signerKind = "software";
  } else if (opts.tier === "os-keychain") {
    signer = await loadOSKeychainSigner(home);
    signerKind = "os_keychain";
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

  // Session key: a fresh Ed25519 keypair per session. Persisted under
  // $AGENTLOCK_HOME so the session can be resumed or signed-for across
  // CLI invocations; discarded on session end.
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
    user_id: opts.userId,
    groups: opts.groups,
  };

  const client = apiClient(opts.url);
  const res = await client.createSession(req);

  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + "\n");
    return;
  }
  process.stdout.write(
    `session: ${res.id}\n` +
      `  started:  ${res.started_at}\n` +
      `  expires:  ${res.expires_at}\n` +
      `  signer:   ${res.signer}\n` +
      `  policy:   ${res.policy_hash}\n`,
  );
}

function readPolicyHash(home: string): string | null {
  const p = join(home, "policy.hash");
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8").trim();
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");
}
