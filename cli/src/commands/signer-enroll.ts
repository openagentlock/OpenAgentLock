import { mkdirSync } from "node:fs";
import { agentlockHome } from "../util/paths";
import { enrollTOTPSigner } from "../signer/totp";

export interface EnrollOptions {
  tier: "totp";
  passphrase: string;
  json: boolean;
  label?: string;
  issuer?: string;
}

export async function runSignerEnroll(opts: EnrollOptions): Promise<void> {
  const home = agentlockHome();
  mkdirSync(home, { recursive: true });

  if (opts.tier !== "totp") {
    throw new Error(`tier ${opts.tier} not wired yet (MVP supports totp)`);
  }

  const e = await enrollTOTPSigner(home, opts.passphrase, {
    label: opts.label,
    issuer: opts.issuer,
  });

  if (opts.json) {
    process.stdout.write(
      JSON.stringify(
        {
          kind: "totp_backed_software",
          secret_base32: e.secretBase32,
          otpauth_uri: e.otpauthUri,
          public_key: `ed25519:${toHex(e.publicKey)}`,
        },
        null,
        2,
      ) + "\n",
    );
    return;
  }
  process.stdout.write(
    `TOTP signer enrolled .\n` +
      `  scan:      ${e.otpauthUri}\n` +
      `  secret:    ${e.secretBase32}\n` +
      `  pubkey:    ed25519:${toHex(e.publicKey)}\n\n` +
      `Next: agentlock session create --tier totp --passphrase <pp> --code <6-digit>\n`,
  );
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");
}
