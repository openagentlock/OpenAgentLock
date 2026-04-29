export type SignerKind =
  | "none"
  | "os_keychain"
  | "totp_backed_software"
  | "yubikey_piv"
  | "yubikey_fido2"
  | "software";

export interface Signer {
  kind: SignerKind;
  publicKey: Uint8Array;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

export interface AttestationPayload {
  policy_hash: string;
  session_pubkey: string;
  signer: SignerKind;
  signer_pubkey: string;
}
