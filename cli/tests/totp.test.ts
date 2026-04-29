// TOTP signer  tests. RFC 6238 vectors pin the code-generation
// primitive; the rest of the suite covers enrollment, seal + unseal,
// wrong-code and wrong-passphrase rejection.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed25519 from "@noble/ed25519";

import {
  generateTOTPCode,
  enrollTOTPSigner,
  loadTOTPSigner,
  FAST_ARGON2_PARAMS,
} from "../src/signer/totp";

const RFC6238_SECRET_ASCII = new TextEncoder().encode("12345678901234567890");

describe("RFC 6238 reference vectors (6-digit, SHA-1, 30s step)", () => {
  const cases: Array<[number, string]> = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
  ];
  for (const [t, want] of cases) {
    test(`T=${t} → ${want}`, async () => {
      const got = await generateTOTPCode(RFC6238_SECRET_ASCII, t);
      expect(got).toBe(want);
    });
  }
});

describe("TOTP signer enrollment + sign round-trip", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentlock-totp-"));
    process.env.AGENTLOCK_ARGON2_FAST = "1";
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    delete process.env.AGENTLOCK_ARGON2_FAST;
  });

  test("enroll writes totp.secret + totp-sealed.key and returns secret + pub", async () => {
    const e = await enrollTOTPSigner(home, "correct-horse-battery-staple");
    expect(e.secretBase32.length).toBeGreaterThanOrEqual(32);
    expect(e.publicKey.length).toBe(32);
    expect(e.otpauthUri.startsWith("otpauth://totp/")).toBe(true);
    expect(existsSync(join(home, "totp-sealed.key"))).toBe(true);
    expect(existsSync(join(home, "totp.secret"))).toBe(true);
  });

  test("load with a fresh TOTP code unseals and signs a valid signature", async () => {
    const e = await enrollTOTPSigner(home, "pp");
    const now = Math.floor(Date.now() / 1000);
    const code = await generateTOTPCode(e.secretBytes, now);
    const s = await loadTOTPSigner(home, { passphrase: "pp", code, now });
    expect(s.kind).toBe("totp_backed_software");
    expect(Buffer.from(s.publicKey).equals(Buffer.from(e.publicKey))).toBe(true);

    const msg = new TextEncoder().encode("hello");
    const sig = await s.sign(msg);
    expect(await ed25519.verifyAsync(sig, msg, s.publicKey)).toBe(true);
  });

  test("wrong code rejects", async () => {
    await enrollTOTPSigner(home, "pp");
    await expect(
      loadTOTPSigner(home, { passphrase: "pp", code: "000000", now: 1_700_000_000 }),
    ).rejects.toThrow(/invalid TOTP code/);
  });

  test("wrong passphrase rejects (unseal fails)", async () => {
    const e = await enrollTOTPSigner(home, "pp");
    const now = Math.floor(Date.now() / 1000);
    const code = await generateTOTPCode(e.secretBytes, now);
    await expect(
      loadTOTPSigner(home, { passphrase: "WRONG", code, now }),
    ).rejects.toThrow(/unseal/);
  });

  test("load without enrollment throws", async () => {
    await expect(
      loadTOTPSigner(home, { passphrase: "pp", code: "000000", now: 1_700_000_000 }),
    ).rejects.toThrow(/not enrolled/);
  });

  test("previous-window code (±1 step) is accepted", async () => {
    const e = await enrollTOTPSigner(home, "pp");
    const now = Math.floor(Date.now() / 1000);
    // Use the code that was valid 30s ago.
    const prevCode = await generateTOTPCode(e.secretBytes, now - 30);
    const s = await loadTOTPSigner(home, { passphrase: "pp", code: prevCode, now });
    expect(s.kind).toBe("totp_backed_software");
  });

  test("FAST params are strictly weaker than production params", () => {
    expect(FAST_ARGON2_PARAMS.m).toBeLessThan(256 * 1024);
    expect(FAST_ARGON2_PARAMS.t).toBeLessThanOrEqual(3);
  });
});
