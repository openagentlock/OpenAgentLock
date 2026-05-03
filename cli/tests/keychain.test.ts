// macOS Keychain-backed signer tests. Skipped on non-darwin because the
// keychain.ts shell-out target (/usr/bin/security) only exists on macOS.
// Each test uses a tempdir-derived account name so we never touch the
// developer's real openagentlock-signer entry, and the afterEach cleanup
// runs `security delete-generic-password` against those temp accounts so
// the login keychain isn't polluted.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import * as ed25519 from "@noble/ed25519";

import { enrollOSKeychainSigner, loadOSKeychainSigner } from "../src/signer/keychain";

const SERVICE = "openagentlock-signer";

function accountFor(home: string): string {
  return "agentlock:" + createHash("sha256").update(home).digest("hex").slice(0, 16);
}

function deleteKeychainEntry(account: string): void {
  spawnSync(
    "/usr/bin/security",
    ["delete-generic-password", "-s", SERVICE, "-a", account],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
}

const describeMac = platform() === "darwin" ? describe : describe.skip;

describeMac("OS-keychain signer (darwin)", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentlock-keychain-"));
  });

  afterEach(() => {
    deleteKeychainEntry(accountFor(home));
    rmSync(home, { recursive: true, force: true });
  });

  test("enroll writes meta + load signs a verifiable signature", async () => {
    const e = await enrollOSKeychainSigner(home);
    expect(e.publicKey.length).toBe(32);
    expect(e.account).toBe(accountFor(home));
    expect(e.expiresAt).toBeNull();

    const s = await loadOSKeychainSigner(home);
    expect(s.kind).toBe("os_keychain");
    expect(Buffer.from(s.publicKey).equals(Buffer.from(e.publicKey))).toBe(true);

    const msg = new TextEncoder().encode("hello");
    const sig = await s.sign(msg);
    expect(await ed25519.verifyAsync(sig, msg, s.publicKey)).toBe(true);
  });

  test("ttl in the future is accepted, expired ttl rejects", async () => {
    await enrollOSKeychainSigner(home, { ttlSeconds: 3600 });
    const s = await loadOSKeychainSigner(home);
    expect(s.kind).toBe("os_keychain");

    // Rewrite meta with an expires_at in the past — simulates a TTL that
    // ran out without forcing the test to actually wait.
    const metaPath = join(home, "os-keychain.meta.json");
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    meta.expires_at = new Date(Date.now() - 1000).toISOString();
    writeFileSync(metaPath, JSON.stringify(meta));

    await expect(loadOSKeychainSigner(home)).rejects.toThrow(/expired/);
  });

  test("re-enroll overwrites the keychain entry and rotates the pubkey", async () => {
    const first = await enrollOSKeychainSigner(home);
    const second = await enrollOSKeychainSigner(home);
    expect(first.account).toBe(second.account);
    expect(Buffer.from(first.publicKey).equals(Buffer.from(second.publicKey))).toBe(false);

    const s = await loadOSKeychainSigner(home);
    expect(Buffer.from(s.publicKey).equals(Buffer.from(second.publicKey))).toBe(true);
  });

  test("meta pubkey checksum mismatch rejects (defence in depth)", async () => {
    await enrollOSKeychainSigner(home);
    const metaPath = join(home, "os-keychain.meta.json");
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    meta.public_key_hex = "00".repeat(32);
    writeFileSync(metaPath, JSON.stringify(meta));
    await expect(loadOSKeychainSigner(home)).rejects.toThrow(/checksum/);
  });

  test("load without enrollment throws", async () => {
    await expect(loadOSKeychainSigner(home)).rejects.toThrow(/not enrolled/);
  });

  test("invalid expires_at in meta rejects", async () => {
    await enrollOSKeychainSigner(home, { ttlSeconds: 3600 });
    const metaPath = join(home, "os-keychain.meta.json");
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    meta.expires_at = "not-a-date";
    writeFileSync(metaPath, JSON.stringify(meta));
    await expect(loadOSKeychainSigner(home)).rejects.toThrow(/invalid expires_at/);
  });
});
