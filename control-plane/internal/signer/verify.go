// Package signer verifies Ed25519 session attestations.
//
// The CLI owns the private key (ADR 0015 decision 3). The control-plane
// only verifies. Keep the canonical-JSON shape byte-identical to
// cli/src/signer/canonical.ts — the TS test and this file's test both
// pin the same fixture string.
package signer

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

type AttestationPayload struct {
	PolicyHash    string
	SessionPubKey string
	Signer        string
	SignerPubKey  string
}

var errInvalidSignature = errors.New("invalid ed25519 signature")

// CanonicalAttestation produces the byte-exact JSON the CLI signs.
// Panics on control-char input — we never emit those, so any caller
// passing one has a bug upstream.
func CanonicalAttestation(p AttestationPayload) []byte {
	fields := []struct {
		key, val string
	}{
		{"policy_hash", p.PolicyHash},
		{"session_pubkey", p.SessionPubKey},
		{"signer", p.Signer},
		{"signer_pubkey", p.SignerPubKey},
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		assertPrintable(f.key, f.val)
		b.WriteByte('"')
		b.WriteString(f.key)
		b.WriteString(`":"`)
		writeEscaped(&b, f.val)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return []byte(b.String())
}

func Verify(pubKey, msg, sig []byte) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("bad ed25519 public key length: got %d want %d", len(pubKey), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bad ed25519 signature length: got %d want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubKey, msg, sig) {
		return errInvalidSignature
	}
	return nil
}

func assertPrintable(key, val string) {
	for i := 0; i < len(val); i++ {
		c := val[i]
		if c < 0x20 || c == 0x7f {
			panic(fmt.Sprintf("CanonicalAttestation: field %s contains control char 0x%02x", key, c))
		}
	}
}

func writeEscaped(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(c)
		}
	}
}
