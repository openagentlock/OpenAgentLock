package signer

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// Byte-exact fixture — must match cli/tests/signer.test.ts FIXTURE_CANONICAL.
// If this string drifts on either side, signatures stop verifying in prod
// but tests catch it first.
const fixtureCanonical = `{"policy_hash":"sha256:abcd1234","session_pubkey":"ed25519:9f8e7d","signer":"software","signer_pubkey":"ed25519:1234abcd"}`

func fixturePayload() AttestationPayload {
	return AttestationPayload{
		PolicyHash:    "sha256:abcd1234",
		SessionPubKey: "ed25519:9f8e7d",
		Signer:        "software",
		SignerPubKey:  "ed25519:1234abcd",
	}
}

func TestCanonicalAttestation_ByteExactFixture(t *testing.T) {
	got := CanonicalAttestation(fixturePayload())
	if string(got) != fixtureCanonical {
		t.Fatalf("canonical mismatch\n want: %q\n  got: %q", fixtureCanonical, got)
	}
}

func TestCanonicalAttestation_RejectsControlChar(t *testing.T) {
	p := fixturePayload()
	p.PolicyHash = "bad\nnewline"
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on control char")
		}
	}()
	CanonicalAttestation(p)
}

func TestVerify_AcceptsValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatalf("expected valid signature to verify: %v", err)
	}
}

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	sig[0] ^= 0xff
	if err := Verify(pub, msg, sig); err == nil {
		t.Fatal("expected tampered signature to fail")
	}
}

func TestVerify_RejectsTamperedMessage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, []byte("hello"))
	if err := Verify(pub, []byte("world"), sig); err == nil {
		t.Fatal("expected wrong-message signature to fail")
	}
}

func TestVerify_RejectsWrongPubKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if err := Verify(other, msg, sig); err == nil {
		t.Fatal("expected wrong-pubkey signature to fail")
	}
}

func TestVerify_RejectsInvalidPubKeyLength(t *testing.T) {
	if err := Verify([]byte{0x00}, []byte("x"), bytes.Repeat([]byte{0x00}, 64)); err == nil {
		t.Fatal("expected bad-length pubkey to fail")
	}
}
