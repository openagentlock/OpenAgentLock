package api

import (
	"crypto/sha256"
	"encoding/hex"
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
	Server      string         `json:"server"`
	Fingerprint string         `json:"fingerprint"`
	ServerInfo  map[string]any `json:"server_info,omitempty"`
}

type pinCheckResponse struct {
	Status           string `json:"status"` // unknown | known | changed
	Server           string `json:"server"`
	Fingerprint      string `json:"fingerprint"`
	KnownFingerprint string `json:"known_fingerprint,omitempty"`
}

type mcpPinRow struct {
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
}

type pendingMCPPinRow struct {
	ID               string         `json:"id"`
	Server           string         `json:"server"`
	Fingerprint      string         `json:"fingerprint"`
	KnownFingerprint string         `json:"known_fingerprint,omitempty"`
	Status           string         `json:"status"`
	ServerInfo       map[string]any `json:"server_info,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type mcpPinsResponse struct {
	Pins    []mcpPinRow        `json:"pins"`
	Pending []pendingMCPPinRow `json:"pending"`
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
		pinFileMu.Lock()
		defer pinFileMu.Unlock()

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
		if resp.Status == "known" {
			if err := removePendingMCPPin(d.PinStorePath, req.Server, req.Fingerprint); err != nil {
				writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
				return
			}
		} else {
			row := pendingMCPPinRow{
				ID:               pendingMCPPinID(req.Server, req.Fingerprint),
				Server:           req.Server,
				Fingerprint:      req.Fingerprint,
				KnownFingerprint: resp.KnownFingerprint,
				Status:           resp.Status,
				ServerInfo:       req.ServerInfo,
			}
			if err := upsertPendingMCPPin(d.PinStorePath, row, time.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func mcpPinsListHandler(d Deps) http.HandlerFunc {
	if d.PinStorePath == "" {
		return todo("mcp.pins.list")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		pinFileMu.Lock()
		defer pinFileMu.Unlock()

		pins, err := readPins(d.PinStorePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		pending, err := readPendingMCPPins(d.PinStorePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		servers := make([]string, 0, len(pins))
		for server := range pins {
			servers = append(servers, server)
		}
		sort.Strings(servers)
		rows := make([]mcpPinRow, 0, len(servers))
		for _, server := range servers {
			rows = append(rows, mcpPinRow{
				Server:      server,
				Fingerprint: pins[server],
			})
		}
		writeJSON(w, http.StatusOK, mcpPinsResponse{Pins: rows, Pending: pending})
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
		if err := removePendingMCPPin(d.PinStorePath, req.Server, req.Fingerprint); err != nil {
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

func mcpPinRefuseHandler(d Deps) http.HandlerFunc {
	if d.PinStorePath == "" {
		return todo("mcp.pin.refuse")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req pinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Server == "" || req.Fingerprint == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "server + fingerprint required")
			return
		}
		pinFileMu.Lock()
		defer pinFileMu.Unlock()
		if err := removePendingMCPPin(d.PinStorePath, req.Server, req.Fingerprint); err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"refused": true,
			"server":  req.Server,
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

func pendingMCPPinsPath(pinStorePath string) string {
	return filepath.Join(filepath.Dir(pinStorePath), "pending-mcp-pins.json")
}

func pendingMCPPinID(server, fingerprint string) string {
	sum := sha256.Sum256([]byte(server + "\x00" + fingerprint))
	return hex.EncodeToString(sum[:16])
}

func readPendingMCPPins(pinStorePath string) ([]pendingMCPPinRow, error) {
	path := pendingMCPPinsPath(pinStorePath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []pendingMCPPinRow{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return []pendingMCPPinRow{}, nil
	}
	var rows []pendingMCPPinRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	sortPendingMCPPins(rows)
	return rows, nil
}

func writePendingMCPPins(pinStorePath string, rows []pendingMCPPinRow) error {
	path := pendingMCPPinsPath(pinStorePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	sortPendingMCPPins(rows)
	if rows == nil {
		rows = []pendingMCPPinRow{}
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	return policy.AtomicWriteFile(path, data, 0o600)
}

func upsertPendingMCPPin(pinStorePath string, row pendingMCPPinRow, now time.Time) error {
	rows, err := readPendingMCPPins(pinStorePath)
	if err != nil {
		return err
	}
	if row.ID == "" {
		row.ID = pendingMCPPinID(row.Server, row.Fingerprint)
	}
	row.UpdatedAt = now
	for i := range rows {
		if rows[i].Server == row.Server && rows[i].Fingerprint == row.Fingerprint {
			row.CreatedAt = rows[i].CreatedAt
			rows[i] = row
			return writePendingMCPPins(pinStorePath, rows)
		}
	}
	row.CreatedAt = now
	rows = append(rows, row)
	return writePendingMCPPins(pinStorePath, rows)
}

func removePendingMCPPin(pinStorePath, server, fingerprint string) error {
	rows, err := readPendingMCPPins(pinStorePath)
	if err != nil {
		return err
	}
	out := rows[:0]
	for _, row := range rows {
		if row.Server == server && row.Fingerprint == fingerprint {
			continue
		}
		out = append(out, row)
	}
	return writePendingMCPPins(pinStorePath, out)
}

func sortPendingMCPPins(rows []pendingMCPPinRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Server != rows[j].Server {
			return rows[i].Server < rows[j].Server
		}
		if rows[i].Fingerprint != rows[j].Fingerprint {
			return rows[i].Fingerprint < rows[j].Fingerprint
		}
		return rows[i].ID < rows[j].ID
	})
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
