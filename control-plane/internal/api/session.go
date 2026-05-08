package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/signer"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

func sessionEndHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("session.end")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := routeParam("/v1/sessions/{id}/end", r.URL.Path, "id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "missing session id")
			return
		}
		sess, err := d.Store.GetSession(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", id)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		if err := d.Store.EndSession(r.Context(), id); err != nil {
			if errors.Is(err, storage.ErrSessionEnded) {
				writeError(w, http.StatusGone, "session_ended", id)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		payloadBytes, _ := json.Marshal(map[string]any{
			"session_id": id,
			"event":      "session.end",
		})
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "system",
			ToolUseID:   "session.end",
			Signer:      sess.Signer,
			PayloadHash: payloadHash[:],
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func sessionRotateHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("session.rotate")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := routeParam("/v1/sessions/{id}/rotate", r.URL.Path, "id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "missing session id")
			return
		}
		existing, err := d.Store.GetSession(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", id)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		active, err := d.Store.IsSessionActive(r.Context(), id)
		if err != nil {
			log.Printf("session.rotate: IsSessionActive: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "session state unavailable")
			return
		}
		if !active {
			writeError(w, http.StatusGone, "session_ended", id)
			return
		}

		var req sessionStartRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if err := validateSessionStart(req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		pub, err := parseEd25519Hex(req.SignerPubKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "signer_pubkey: "+err.Error())
			return
		}
		sig, err := parseEd25519Sig(req.Attestation)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "attestation: "+err.Error())
			return
		}
		canon := signer.CanonicalAttestation(signer.AttestationPayload{
			PolicyHash:    req.PolicyHash,
			SessionPubKey: req.SessionPubKey,
			Signer:        req.Signer,
			SignerPubKey:  req.SignerPubKey,
		})
		if err := signer.Verify(pub, canon, sig); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
			return
		}

		now := time.Now().UTC()
		updated := existing
		updated.PolicyHash = req.PolicyHash
		updated.SessionPubKey = req.SessionPubKey
		updated.Signer = req.Signer
		updated.SignerPubKey = req.SignerPubKey
		updated.ExpiresAt = now.Add(sessionTTL)
		if trimmed := strings.TrimSpace(req.UserID); trimmed != "" {
			updated.UserID = trimmed
		}
		if req.Groups != nil {
			updated.Groups = dedupeStrings(req.Groups)
		}
		if err := d.Store.UpdateSession(r.Context(), updated); err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		payloadHash := sha256.Sum256(canon)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          now,
			Source:      "system",
			ToolUseID:   "session.rotate",
			Signer:      req.Signer,
			PayloadHash: payloadHash[:],
			Sig:         sig,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// routeParam is a tiny helper to pull a {name} segment out of the URL path
// given the canonical pattern. Avoids importing a router.
func routeParam(pattern, path, name string) string {
	ps := splitTrim(pattern)
	xs := splitTrim(path)
	if len(ps) != len(xs) {
		return ""
	}
	for i, p := range ps {
		if p == "{"+name+"}" {
			return xs[i]
		}
	}
	return ""
}

func splitTrim(s string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

type sessionStartRequest struct {
	PolicyHash    string   `json:"policy_hash"`
	SessionPubKey string   `json:"session_pubkey"`
	Signer        string   `json:"signer"`
	SignerPubKey  string   `json:"signer_pubkey"`
	Attestation   string   `json:"attestation"`
	Harness       string   `json:"harness,omitempty"`
	UserID        string   `json:"user_id,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// current accepted signer kinds. Mirrors docs/guide/signers.md. "none" is valid on
// the Unattested path but session.create still requires a key; Unattested
// sessions skip this endpoint entirely, so we reject it here.
var acceptedSignerKinds = map[string]struct{}{
	"software":             {},
	"os_keychain":          {},
	"totp_backed_software": {},
	"yubikey_piv":          {},
	"yubikey_fido2":        {},
}

const sessionTTL = 4 * time.Hour

func createSessionHandler(d Deps) http.HandlerFunc {
	// If dependencies aren't wired (bare router in legacy tests) fall back
	// to the 501 path so the 501-contract test keeps passing for other
	// routes while /v1/sessions is dropped from that test's list.
	if d.Store == nil {
		return todo("session.create")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req sessionStartRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if err := validateSessionStart(req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		pub, err := parseEd25519Hex(req.SignerPubKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "signer_pubkey: "+err.Error())
			return
		}
		sig, err := parseEd25519Sig(req.Attestation)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "attestation: "+err.Error())
			return
		}
		canon := signer.CanonicalAttestation(signer.AttestationPayload{
			PolicyHash:    req.PolicyHash,
			SessionPubKey: req.SessionPubKey,
			Signer:        req.Signer,
			SignerPubKey:  req.SignerPubKey,
		})
		if err := signer.Verify(pub, canon, sig); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
			return
		}

		now := time.Now().UTC()
		s := storage.Session{
			ID:            newSessionID(now),
			StartedAt:     now,
			ExpiresAt:     now.Add(sessionTTL),
			PolicyHash:    req.PolicyHash,
			SessionPubKey: req.SessionPubKey,
			Signer:        req.Signer,
			SignerPubKey:  req.SignerPubKey,
			Harness:       strings.TrimSpace(req.Harness),
			UserID:        strings.TrimSpace(req.UserID),
			Groups:        dedupeStrings(req.Groups),
		}
		if err := d.Store.CreateSession(r.Context(), s); err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(canon)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          now,
			Source:      "system",
			ToolUseID:   "session.create",
			Signer:      req.Signer,
			PayloadHash: payloadHash[:],
			Sig:         sig,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, s)
	}
}

func validateSessionStart(r sessionStartRequest) error {
	if r.PolicyHash == "" {
		return errors.New("policy_hash required")
	}
	if r.SessionPubKey == "" {
		return errors.New("session_pubkey required")
	}
	if r.SignerPubKey == "" {
		return errors.New("signer_pubkey required")
	}
	if r.Attestation == "" {
		return errors.New("attestation required")
	}
	if r.Signer == "" {
		return errors.New("signer required")
	}
	if _, ok := acceptedSignerKinds[r.Signer]; !ok {
		return errors.New("unknown signer kind: " + r.Signer)
	}
	return nil
}

// parseEd25519Hex strips an optional "ed25519:" prefix and hex-decodes the
// remainder, expecting an Ed25519 public-key length.
func parseEd25519Hex(s string) (ed25519.PublicKey, error) {
	raw := strings.TrimPrefix(s, "ed25519:")
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("wrong public-key length")
	}
	return b, nil
}

func parseEd25519Sig(s string) ([]byte, error) {
	raw := strings.TrimPrefix(s, "ed25519:")
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SignatureSize {
		return nil, errors.New("wrong signature length")
	}
	return b, nil
}

// newSessionID is a light ULID-ish: 48-bit ms timestamp + 80-bit randomness,
// Crockford base32, 26 chars. Good enough for sortable unique ids without
// pulling a dependency.
func newSessionID(t time.Time) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out [26]byte
	ms := uint64(t.UnixMilli())
	// 10 chars for the timestamp, 16 for the random part.
	for i := 9; i >= 0; i-- {
		out[i] = alphabet[ms&0x1f]
		ms >>= 5
	}
	var rnd [10]byte
	_, _ = rand.Read(rnd[:])
	bits := uint64(0)
	held := 0
	di := 10
	for _, b := range rnd {
		bits = (bits << 8) | uint64(b)
		held += 8
		for held >= 5 && di < 26 {
			held -= 5
			out[di] = alphabet[(bits>>held)&0x1f]
			di++
		}
	}
	for di < 26 {
		out[di] = alphabet[0]
		di++
	}
	return string(out[:])
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]string{"error": code, "detail": detail})
}
