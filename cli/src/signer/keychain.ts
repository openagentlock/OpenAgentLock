// macOS Keychain-backed software signer.
//
// Enrollment: generate ed25519 seed, hand off to the login keychain via
//   `security add-generic-password -U -s <service> -a <account> -w <hex>`
// where <account> is derived from $AGENTLOCK_HOME so different agentlock
// instances don't collide. We additionally persist a small JSON meta file
// holding pubkey + expires_at (if a TTL was given at enrollment); load
// rejects expired entries before going near the keychain.
//
// macOS doesn't expose a native TTL on keychain items, so the TTL is
// purely an OpenAgentLock-side check. The keychain entry itself stays
// until `security delete-generic-password` runs (handled implicitly when
// the user re-enrolls with `-U`).
//
// Linux/Windows fall back to a clear "not implemented" error — Secret
// Service / DPAPI bindings are roadmap items.

import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { platform } from "node:os";
import * as ed25519 from "@noble/ed25519";
import type { Signer } from "./types";

const SERVICE = "openagentlock-signer";
const META_FILE = "os-keychain.meta.json";

interface KeychainMeta {
  service: string;
  account: string;
  public_key_hex: string;
  enrolled_at: string;
  expires_at: string | null;
}

function ensureMac(): void {
  if (platform() !== "darwin") {
    throw new Error(
      `os-keychain signer is macOS-only today (got platform=${platform()}). ` +
        `Linux Secret Service / Windows DPAPI are on the roadmap.`,
    );
  }
}

function accountFor(home: string): string {
  // Stable per AGENTLOCK_HOME so a developer juggling repo sandboxes vs
  // their real ~/Library/Application Support/OpenAgentLock home doesn't
  // overwrite one with the other.
  return "agentlock:" + createHash("sha256").update(home).digest("hex").slice(0, 16);
}

function keychainStore(account: string, hexSeed: string): void {
  // -U updates if the item already exists (re-enroll path).
  const r = spawnSync(
    "/usr/bin/security",
    ["add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", hexSeed],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) {
    throw new Error(`security add-generic-password failed (exit ${r.status}): ${r.stderr.trim()}`);
  }
}

function keychainFetch(account: string): Uint8Array {
  const r = spawnSync(
    "/usr/bin/security",
    ["find-generic-password", "-s", SERVICE, "-a", account, "-w"],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) {
    throw new Error(
      `security find-generic-password failed (exit ${r.status}): ${r.stderr.trim()}. ` +
        `Re-enroll with: agentlock signer enroll --tier os-keychain`,
    );
  }
  const hex = r.stdout.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`keychain entry for ${account} is not a 32-byte hex seed`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface EnrollKeychainResult {
  publicKey: Uint8Array;
  account: string;
  expiresAt: string | null;
}

export interface EnrollKeychainOptions {
  ttlSeconds?: number;
}

export async function enrollOSKeychainSigner(
  home: string,
  opts?: EnrollKeychainOptions,
): Promise<EnrollKeychainResult> {
  ensureMac();
  mkdirSync(home, { recursive: true });

  const seed = new Uint8Array(randomBytes(32));
  const account = accountFor(home);
  const hex = Array.from(seed, (v) => v.toString(16).padStart(2, "0")).join("");
  keychainStore(account, hex);

  const pub = await ed25519.getPublicKeyAsync(seed);
  const enrolledAt = new Date();
  const expiresAt =
    opts?.ttlSeconds && opts.ttlSeconds > 0
      ? new Date(enrolledAt.getTime() + opts.ttlSeconds * 1000)
      : null;

  const meta: KeychainMeta = {
    service: SERVICE,
    account,
    public_key_hex: Array.from(pub, (v) => v.toString(16).padStart(2, "0")).join(""),
    enrolled_at: enrolledAt.toISOString(),
    expires_at: expiresAt ? expiresAt.toISOString() : null,
  };
  const metaPath = join(home, META_FILE);
  writeFileSync(metaPath, JSON.stringify(meta, null, 2) + "\n", { mode: 0o600 });
  chmodSync(metaPath, 0o600);

  return { publicKey: pub, account, expiresAt: meta.expires_at };
}

export async function loadOSKeychainSigner(home: string): Promise<Signer> {
  ensureMac();
  const metaPath = join(home, META_FILE);
  if (!existsSync(metaPath)) {
    throw new Error(
      "os-keychain signer not enrolled: run `agentlock signer enroll --tier os-keychain` first",
    );
  }
  const meta = JSON.parse(readFileSync(metaPath, "utf8")) as KeychainMeta;
  if (meta.expires_at) {
    const exp = Date.parse(meta.expires_at);
    if (Number.isNaN(exp)) {
      throw new Error(`${metaPath}: invalid expires_at "${meta.expires_at}"`);
    }
    if (Date.now() >= exp) {
      throw new Error(
        `os-keychain signer expired at ${meta.expires_at}. ` +
          `Re-enroll with: agentlock signer enroll --tier os-keychain --ttl <duration>`,
      );
    }
  }

  const seed = keychainFetch(meta.account);
  const pub = await ed25519.getPublicKeyAsync(seed);

  // Defence in depth: the keychain entry could in theory have been
  // rewritten out of band. Reject if the on-disk pubkey checksum no
  // longer matches the seed we just unwrapped.
  const pubHex = Array.from(pub, (v) => v.toString(16).padStart(2, "0")).join("");
  if (pubHex !== meta.public_key_hex) {
    throw new Error(
      "os-keychain seed does not match enrolled pubkey checksum — re-enroll with `agentlock signer enroll --tier os-keychain`",
    );
  }

  return {
    kind: "os_keychain",
    publicKey: pub,
    async sign(msg: Uint8Array): Promise<Uint8Array> {
      return ed25519.signAsync(msg, seed);
    },
  };
}
