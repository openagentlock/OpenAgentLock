import { mkdirSync } from "node:fs";
// qrcode-terminal ships no types; this is the entire surface we use.
// @ts-expect-error — no @types/qrcode-terminal package
import qrcode from "qrcode-terminal";
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
    throw new Error(
      `tier ${opts.tier} is not supported by signer enroll. Currently supported: totp. ` +
        `OS-keychain and hardware-key (YubiKey) tiers are on the roadmap.`,
    );
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
    `TOTP signer enrolled.\n\n` +
      `  scan with your authenticator app (Google Authenticator / 1Password / Authy):\n\n`,
  );
  // qrcode.generate writes the QR directly to stdout. small=true uses
  // half-block characters so the code fits in a typical terminal.
  qrcode.generate(e.otpauthUri, { small: true });
  process.stdout.write(
    `\n  manual setup (if your terminal mangles the QR):\n` +
      `    secret: ${e.secretBase32}\n` +
      `    type:   TOTP, SHA1, 6 digits, 30s\n` +
      `    raw uri: ${e.otpauthUri}\n` +
      `  signing public key:\n` +
      `    ed25519:${toHex(e.publicKey)}\n\n` +
      `Next steps:\n` +
      `  agentlock install --tier totp --code <6-digit> --passphrase <pp>\n` +
      `or, for an explicit session:\n` +
      `  agentlock session create --tier totp --code <6-digit> --passphrase <pp>\n`,
  );
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");
}
