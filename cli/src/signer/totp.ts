// TOTP-backed software signer.
//
// Enrollment:
//   - generate 20 random bytes as the shared TOTP secret (RFC 6238)
//   - generate an Ed25519 signing seed
//   - seal the seed with argon2id(password = TOTP secret || passphrase,
//     salt = per-enrollment 16-byte salt). XOR the derived key against the
//     raw seed to produce the "sealed" blob.
//   - persist:
//       totp-sealed.key     16-byte salt || 32-byte sealed seed
//       totp.secret         raw 20 bytes (dev convenience so tests can
//                           compute codes; warn user to scan + delete).
//
// Session load:
//   - read totp-sealed.key and totp.secret
//   - verify the current code matches one of the ±1 windows
//   - derive the argon2id key again and unseal → Ed25519 seed
//   - return a Signer whose sign() closes over the seed in memory.
//
// The Argon2id params follow docs/guide/signers.md TOTP spec (256 MiB, 3 iter)
// in production. `AGENTLOCK_ARGON2_FAST=1` switches to params that run in
// ~milliseconds for unit tests.

import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import * as ed25519 from "@noble/ed25519";
import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import type { Signer } from "./types";

const PROD_ARGON2_PARAMS = { t: 3, m: 256 * 1024, p: 1, dkLen: 32 } as const;
export const FAST_ARGON2_PARAMS = { t: 1, m: 64, p: 1, dkLen: 32 } as const;

const SALT_LEN = 16;
const SEED_LEN = 32;
const SECRET_LEN = 20;
const CODE_DIGITS = 6;
const STEP_SECONDS = 30;

function argonParams() {
  return process.env.AGENTLOCK_ARGON2_FAST === "1" ? FAST_ARGON2_PARAMS : PROD_ARGON2_PARAMS;
}

// ---------- TOTP primitive ----------

export async function generateTOTPCode(secret: Uint8Array, unixSeconds: number): Promise<string> {
  const counter = Math.floor(unixSeconds / STEP_SECONDS);
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000));
  view.setUint32(4, counter >>> 0);
  const mac = hmac(sha1, secret, buf);
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);
  const code = (bin % 10 ** CODE_DIGITS).toString().padStart(CODE_DIGITS, "0");
  return code;
}

async function verifyCode(secret: Uint8Array, code: string, now: number): Promise<boolean> {
  for (const delta of [-1, 0, 1]) {
    const candidate = await generateTOTPCode(secret, now + delta * STEP_SECONDS);
    if (timingSafeEqualStr(candidate, code)) return true;
  }
  return false;
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- base32 (RFC 4648, no padding) ----------

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 0x1f];
  return out;
}

// ---------- seal / unseal ----------

async function deriveKey(
  secret: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const pw = new Uint8Array([...secret, ...new TextEncoder().encode(passphrase)]);
  return argon2idAsync(pw, salt, argonParams());
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

// ---------- enrollment + load ----------

export interface EnrollResult {
  secretBytes: Uint8Array;
  secretBase32: string;
  publicKey: Uint8Array;
  otpauthUri: string;
}

export async function enrollTOTPSigner(
  home: string,
  passphrase: string,
  opts?: { label?: string; issuer?: string },
): Promise<EnrollResult> {
  mkdirSync(home, { recursive: true });
  const secret = new Uint8Array(randomBytes(SECRET_LEN));
  const seed = new Uint8Array(randomBytes(SEED_LEN));
  const salt = new Uint8Array(randomBytes(SALT_LEN));

  const derived = await deriveKey(secret, passphrase, salt);
  const sealed = xor(seed, derived);

  const blob = new Uint8Array(salt.length + sealed.length);
  blob.set(salt, 0);
  blob.set(sealed, salt.length);
  writeFileSync(join(home, "totp-sealed.key"), blob, { mode: 0o600 });
  chmodSync(join(home, "totp-sealed.key"), 0o600);

  writeFileSync(join(home, "totp.secret"), secret, { mode: 0o600 });
  chmodSync(join(home, "totp.secret"), 0o600);

  // Stash the enrolled pubkey as a checksum so a later unseal with the
  // wrong passphrase can be rejected with a clear error rather than
  // silently producing a garbage key.
  const pubAtEnroll = await ed25519.getPublicKeyAsync(seed);
  writeFileSync(join(home, "totp-checksum.bin"), pubAtEnroll, { mode: 0o600 });
  chmodSync(join(home, "totp-checksum.bin"), 0o600);

  const base32 = base32Encode(secret);
  const label = opts?.label ?? "agentlock";
  const issuer = opts?.issuer ?? "OpenAgentLock";
  const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(
    label,
  )}?secret=${base32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${CODE_DIGITS}&period=${STEP_SECONDS}`;

  const pub = await ed25519.getPublicKeyAsync(seed);
  return { secretBytes: secret, secretBase32: base32, publicKey: pub, otpauthUri: uri };
}

export interface LoadOpts {
  passphrase: string;
  code: string;
  now?: number;
}

export async function loadTOTPSigner(home: string, opts: LoadOpts): Promise<Signer> {
  const sealedPath = join(home, "totp-sealed.key");
  const secretPath = join(home, "totp.secret");
  if (!existsSync(sealedPath) || !existsSync(secretPath)) {
    throw new Error("TOTP signer not enrolled: run `agentlock signer enroll --tier totp` first");
  }
  const blob = new Uint8Array(readFileSync(sealedPath));
  if (blob.length !== SALT_LEN + SEED_LEN) {
    throw new Error(`${sealedPath}: corrupt sealed blob (length ${blob.length})`);
  }
  const salt = blob.slice(0, SALT_LEN);
  const sealed = blob.slice(SALT_LEN);
  const secret = new Uint8Array(readFileSync(secretPath));
  if (secret.length !== SECRET_LEN) {
    throw new Error(
      `${secretPath}: invalid TOTP secret length (got ${secret.length}, want ${SECRET_LEN})`,
    );
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (!(await verifyCode(secret, opts.code, now))) {
    throw new Error("invalid TOTP code");
  }

  const derived = await deriveKey(secret, opts.passphrase, salt);
  const seed = xor(sealed, derived);

  // The enrollment step stashed the pubkey derived from the real seed.
  // A wrong passphrase here unseals to a different seed, hence different
  // pubkey. Compare in constant time and fail loudly rather than handing
  // back a garbage signer that would only surface as a daemon 401.
  const pub = await ed25519.getPublicKeyAsync(seed);
  const checksumPath = join(home, "totp-checksum.bin");
  if (!existsSync(checksumPath)) {
    throw new Error("TOTP enrollment is missing its checksum — re-enroll");
  }
  const expected = new Uint8Array(readFileSync(checksumPath));
  if (expected.length !== 32 || !constantTimeBytesEqual(expected, pub)) {
    throw new Error("TOTP unseal failed (wrong passphrase?)");
  }

  return {
    kind: "totp_backed_software",
    publicKey: pub,
    async sign(msg: Uint8Array): Promise<Uint8Array> {
      return ed25519.signAsync(msg, seed);
    },
  };
}

function constantTimeBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
