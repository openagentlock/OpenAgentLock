// Signer + canonical-JSON tests. TDD red phase written first.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalAttestation, signAttestation } from "../src/signer/canonical";
import { loadOrCreateSoftwareSigner } from "../src/signer/software";
import * as ed25519 from "@noble/ed25519";

// The fixture is the contract. Go's canonical form must produce byte-
// identical output for the same input. Any drift fails tests on both sides
// before it becomes a runtime signature-verification failure.
const FIXTURE_PAYLOAD = {
  policy_hash: "sha256:abcd1234",
  session_pubkey: "ed25519:9f8e7d",
  signer: "software" as const,
  signer_pubkey: "ed25519:1234abcd",
};
const FIXTURE_CANONICAL =
  '{"policy_hash":"sha256:abcd1234","session_pubkey":"ed25519:9f8e7d","signer":"software","signer_pubkey":"ed25519:1234abcd"}';

describe("canonical JSON", () => {
  test("byte-exact for fixture payload", () => {
    const out = canonicalAttestation(FIXTURE_PAYLOAD);
    expect(out).toBe(FIXTURE_CANONICAL);
  });

  test("key order is independent of input order", () => {
    const reordered = {
      signer_pubkey: FIXTURE_PAYLOAD.signer_pubkey,
      signer: FIXTURE_PAYLOAD.signer,
      session_pubkey: FIXTURE_PAYLOAD.session_pubkey,
      policy_hash: FIXTURE_PAYLOAD.policy_hash,
    };
    expect(canonicalAttestation(reordered)).toBe(FIXTURE_CANONICAL);
  });

  test("rejects values containing control chars (we never emit them)", () => {
    expect(() =>
      canonicalAttestation({ ...FIXTURE_PAYLOAD, policy_hash: "bad\nnewline" }),
    ).toThrow();
  });
});

describe("signAttestation", () => {
  test("produces a valid Ed25519 signature that verifies", async () => {
    const seed = new Uint8Array(32).fill(7);
    const pub = await ed25519.getPublicKeyAsync(seed);
    const sig = await signAttestation(FIXTURE_PAYLOAD, seed);
    const msg = new TextEncoder().encode(FIXTURE_CANONICAL);
    expect(await ed25519.verifyAsync(sig, msg, pub)).toBe(true);
  });

  test("signature changes when payload changes", async () => {
    const seed = new Uint8Array(32).fill(7);
    const a = await signAttestation(FIXTURE_PAYLOAD, seed);
    const b = await signAttestation(
      { ...FIXTURE_PAYLOAD, policy_hash: "sha256:deadbeef" },
      seed,
    );
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("software signer ", () => {
  let home: string;
  let prevAllow: string | undefined;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentlock-signer-"));
    prevAllow = process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER;
    delete process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER;
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    if (prevAllow === undefined) delete process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER;
    else process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER = prevAllow;
  });

  test("refuses to initialize without the allow env flag", async () => {
    await expect(loadOrCreateSoftwareSigner(home)).rejects.toThrow(
      /AGENTLOCK_ALLOW_SOFTWARE_SIGNER/,
    );
  });

  test("creates a 32-byte seed at session.key with mode 0600 on first call", async () => {
    process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER = "1";
    const signer = await loadOrCreateSoftwareSigner(home);
    expect(signer.kind).toBe("software");
    expect(signer.publicKey.length).toBe(32);

    const key = join(home, "session.key");
    expect(existsSync(key)).toBe(true);
    const st = statSync(key);
    expect(st.size).toBe(32);
    if (process.platform !== "win32") {
      // 0600 = 384 decimal. Mode bits contain file-type; mask to permission.
      expect(st.mode & 0o777).toBe(0o600);
    }
  });

  test("is deterministic: second load returns the same pubkey", async () => {
    process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER = "1";
    const a = await loadOrCreateSoftwareSigner(home);
    const b = await loadOrCreateSoftwareSigner(home);
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(true);
  });

  test("sign() produces a valid signature the pubkey verifies", async () => {
    process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER = "1";
    const signer = await loadOrCreateSoftwareSigner(home);
    const msg = new TextEncoder().encode("hello");
    const sig = await signer.sign(msg);
    expect(await ed25519.verifyAsync(sig, msg, signer.publicKey)).toBe(true);
  });
});
