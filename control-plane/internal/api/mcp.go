package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type ledgerInputForPin struct {
	Source, ToolUseID, Signer, Payload string
}

// One process-wide lock serialises MCP pin file I/O across the check +
// accept endpoints. The pin-tofu evaluator holds its own mutex; we
// accept that for the demo flow because these endpoints are low-volume
// (human speed).
var pinFileMu sync.Mutex

type pinRequest struct {
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
}

type pinCheckResponse struct {
	Status           string `json:"status"` // unknown | known | changed
	Server           string `json:"server"`
	Fingerprint      string `json:"fingerprint"`
	KnownFingerprint string `json:"known_fingerprint,omitempty"`
}

func mcpPinCheckHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.PinStorePath == "" {
		return todo("mcp.pin.check")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req pinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Server == "" || req.Fingerprint == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "server + fingerprint required")
			return
		}
		pins, err := readPins(d.PinStorePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		resp := pinCheckResponse{Server: req.Server, Fingerprint: req.Fingerprint}
		known, ok := pins[req.Server]
		switch {
		case !ok:
			resp.Status = "unknown"
		case known == req.Fingerprint:
			resp.Status = "known"
		default:
			resp.Status = "changed"
			resp.KnownFingerprint = known
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func mcpPinAcceptHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.PinStorePath == "" {
		return todo("mcp.pin.accept")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req pinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Server == "" || req.Fingerprint == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "server + fingerprint required")
			return
		}
		pinFileMu.Lock()
		defer pinFileMu.Unlock()
		pins, err := readPins(d.PinStorePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		pins[req.Server] = req.Fingerprint
		if err := writePins(d.PinStorePath, pins); err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		// Record the accept in the ledger so there's an audit trail of
		// human-driven pin changes. The pin file is already persisted;
		// a ledger write failure here is logged but does not block the
		// client response — best-effort audit, not the system of record.
		body := fakePinLedgerInput(req)
		ph := sha256.Sum256([]byte(body.Payload))
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      body.Source,
			ToolUseID:   body.ToolUseID,
			Signer:      body.Signer,
			PayloadHash: ph[:],
		}); err != nil {
			log.Printf("mcp.pin.accept: ledger append failed: %v", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted": true,
			"server":   req.Server,
		})
	}
}

// readPins loads the same JSON {server: fingerprint} format the policy
// pin-tofu evaluator maintains. Missing file → empty map, not error.
func readPins(path string) (map[string]string, error) {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	if len(data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func writePins(path string, pins map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Deterministic JSON: sorted keys, no whitespace.
	b := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, fmt.Sprintf("%q:%q", k, pins[k])...)
	}
	b = append(b, '}')
	return policy.AtomicWriteFile(path, b, 0o600)
}

// fakePinLedgerInput builds a minimal AppendInput describing a pin accept.
// Defined as a function so the handler's test double can exercise it.
func fakePinLedgerInput(req pinRequest) ledgerInputForPin {
	return ledgerInputForPin{
		Source:    "tui",
		ToolUseID: "mcp.pin.accept",
		Signer:    "tui",
		Payload:   fmt.Sprintf(`{"server":%q,"fingerprint":%q}`, req.Server, req.Fingerprint),
	}
}
