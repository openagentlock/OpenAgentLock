import * as ed25519 from "@noble/ed25519";
import { mkdirSync, readFileSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { Signer } from "./types";

// Software signer (dev/CI only). Dev/CI only per docs/guide/signers.md. Release builds
// must refuse to default to this kind. Gated on AGENTLOCK_ALLOW_SOFTWARE_SIGNER=1
// so that a user cannot accidentally end up on software by leaving the default.
export async function loadOrCreateSoftwareSigner(agentlockHome: string): Promise<Signer> {
  if (process.env.AGENTLOCK_ALLOW_SOFTWARE_SIGNER !== "1") {
    throw new Error(
      "software signer refused: set AGENTLOCK_ALLOW_SOFTWARE_SIGNER=1 (dev/CI only; see docs/guide/signers.md)",
    );
  }

  mkdirSync(agentlockHome, { recursive: true });
  const keyPath = join(agentlockHome, "session.key");

  let seed: Uint8Array;
  if (existsSync(keyPath)) {
    seed = new Uint8Array(readFileSync(keyPath));
    if (seed.length !== 32) {
      throw new Error(`${keyPath}: expected 32-byte seed, got ${seed.length}`);
    }
  } else {
    seed = new Uint8Array(randomBytes(32));
    writeFileSync(keyPath, seed, { mode: 0o600 });
    chmodSync(keyPath, 0o600);
  }

  const publicKey = await ed25519.getPublicKeyAsync(seed);

  return {
    kind: "software",
    publicKey,
    async sign(msg: Uint8Array): Promise<Uint8Array> {
      return ed25519.signAsync(msg, seed);
    },
  };
}
