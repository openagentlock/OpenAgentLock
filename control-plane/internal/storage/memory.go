// In-memory session store + append-only JSONL ledger writer.
//
// Sessions live in RAM; they reset when the daemon restarts. Ledger
// entries persist to $AGENTLOCK_HOME/ledger.jsonl, mode 0600. Future
// slices may swap both for SQLite, but the interface here is already
// the one the handlers code against.

package storage

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/guardrails"
	"github.com/openagentlock/openagentlock/control-plane/internal/ledger"
)

var (
	ErrSessionExists   = errors.New("session already exists")
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionEnded    = errors.New("session already ended")
)

type Session struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	PolicyHash    string    `json:"policy_hash"`
	SessionPubKey string    `json:"session_pubkey"`
	Signer        string    `json:"signer"`
	SignerPubKey  string    `json:"signer_pubkey"`
	// Harness names the agent runtime this session represents
	// (claude-code, cursor, tui, system, ...). Set at session-create from
	// the incoming hook body or the request. Blank on pre-harness-aware
	// sessions; UI renders those as "unknown".
	Harness string   `json:"harness,omitempty"`
	UserID  string   `json:"user_id,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

type AppendInput struct {
	TS        time.Time
	Source    string
	ToolUseID string
	// Tool is the tool name (Bash, Read, Write, mcp__X__Y) the harness
	// invoked. Distinct from ToolUseID, which is the per-call correlation
	// id. Empty for non-decision events (session lifecycle).
	Tool    string
	Signer  string
	RuleID  string
	Verdict string
	// MonitorMatch is true when the matched gate's verdict was deny but
	// the daemon was in monitor mode at decision time, so the runtime
	// returned allow. The ledger keeps the original deny under Verdict
	// for audit, and dashboards render this flag as "alert" rather than
	// a hard "deny" so monitor mode looks like an IDS, not an IPS.
	MonitorMatch bool
	MatcherInput map[string]string
	PolicyTrace  []PolicyTraceItem
	PayloadHash  []byte
	Sig          []byte
}

type PolicyTraceItem struct {
	Layer      string `json:"layer,omitempty"`
	Source     string `json:"source,omitempty"`
	RuleID     string `json:"rule_id"`
	Verdict    string `json:"verdict"`
	Precedence string `json:"precedence,omitempty"`
	Priority   int    `json:"priority,omitempty"`
}

type LedgerEntry struct {
	Seq          uint64            `json:"seq"`
	TS           time.Time         `json:"ts"`
	Source       string            `json:"source"`
	Tool         string            `json:"tool,omitempty"`
	ToolUseID    string            `json:"tool_use_id"`
	Signer       string            `json:"signer"`
	Input        map[string]string `json:"input,omitempty"`
	RuleID       string            `json:"rule_id,omitempty"`
	Verdict      string            `json:"verdict,omitempty"`
	MonitorMatch bool              `json:"monitor_match,omitempty"`
	PolicyTrace  []PolicyTraceItem `json:"policy_trace,omitempty"`
	PayloadHash  string            `json:"payload_hash"`
	Sig          string            `json:"sig"`
	LeafHash     [32]byte          `json:"-"`
	PrevLeaf     [32]byte          `json:"-"`
	LeafHashHex  string            `json:"leaf_hash"`
	PrevLeafHex  string            `json:"prev_leaf"`
}

type Memory struct {
	mu                       sync.Mutex
	sessions                 map[string]Session
	endedSess                map[string]struct{}
	detects                  map[string][]Detection
	guardrailProviderConfigs map[string]guardrails.ProviderConfig
	guardrailEnabled         []guardrails.EnabledEntry
	home                     string
	nextSeq                  uint64
	lastLeaf                 [32]byte
	ledgerFile               *os.File

	subMu       sync.Mutex
	subscribers map[int]chan LedgerEntry
	nextSubID   int
}

func NewMemory(home string) (*Memory, error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", home, err)
	}
	p := filepath.Join(home, "ledger.jsonl")

	// Resume chain state from any existing ledger file so the chain never
	// breaks across daemon restarts. Without this, a fresh Memory would
	// emit seq=0 + prev_leaf=0 again and silently diverge from prior leaves.
	nextSeq, lastLeaf, err := resumeFromFile(p)
	if err != nil {
		return nil, fmt.Errorf("resume %s: %w", p, err)
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return nil, fmt.Errorf("chmod %s: %w", p, err)
	}
	return &Memory{
		sessions:                 make(map[string]Session),
		endedSess:                make(map[string]struct{}),
		detects:                  make(map[string][]Detection),
		guardrailProviderConfigs: make(map[string]guardrails.ProviderConfig),
		home:                     home,
		ledgerFile:               f,
		nextSeq:                  nextSeq,
		lastLeaf:                 lastLeaf,
		subscribers:              make(map[int]chan LedgerEntry),
	}, nil
}

func (m *Memory) SaveDetections(_ context.Context, sessionID string, dets []Detection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionID]; !ok {
		return ErrSessionNotFound
	}
	m.detects[sessionID] = append([]Detection(nil), dets...)
	return nil
}

func (m *Memory) GetDetections(_ context.Context, sessionID string) ([]Detection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionID]; !ok {
		return nil, ErrSessionNotFound
	}
	return append([]Detection(nil), m.detects[sessionID]...), nil
}

func (m *Memory) SaveGuardrailProviderConfig(_ context.Context, cfg guardrails.ProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.guardrailProviderConfigs == nil {
		m.guardrailProviderConfigs = map[string]guardrails.ProviderConfig{}
	}
	cfg.Metadata = cloneStringMap(cfg.Metadata)
	m.guardrailProviderConfigs[cfg.ProviderID] = cfg
	return nil
}

func (m *Memory) GetGuardrailProviderConfig(_ context.Context, providerID string) (guardrails.ProviderConfig, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.guardrailProviderConfigs[providerID]
	if !ok {
		return guardrails.ProviderConfig{}, false, nil
	}
	cfg.Metadata = cloneStringMap(cfg.Metadata)
	return cfg, true, nil
}

func (m *Memory) ListGuardrailProviderConfigs(_ context.Context) ([]guardrails.ProviderConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]guardrails.ProviderConfig, 0, len(m.guardrailProviderConfigs))
	for _, cfg := range m.guardrailProviderConfigs {
		cfg.Metadata = cloneStringMap(cfg.Metadata)
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ProviderID < out[j].ProviderID
	})
	return out, nil
}

func (m *Memory) SaveGuardrailEnabled(_ context.Context, entries []guardrails.EnabledEntry) ([]guardrails.EnabledEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.guardrailEnabled = append([]guardrails.EnabledEntry(nil), entries...)
	return cloneEnabledEntries(m.guardrailEnabled), nil
}

func (m *Memory) ListGuardrailEnabled(_ context.Context) ([]guardrails.EnabledEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneEnabledEntries(m.guardrailEnabled), nil
}

func cloneEnabledEntries(entries []guardrails.EnabledEntry) []guardrails.EnabledEntry {
	if len(entries) == 0 {
		return []guardrails.EnabledEntry{}
	}
	return append([]guardrails.EnabledEntry(nil), entries...)
}

// Subscribe returns a channel that receives every entry AppendLedger
// writes, starting after subscription. Caller must call the returned
// cancel fn to release the slot.
func (m *Memory) Subscribe(buffer int) (<-chan LedgerEntry, func()) {
	if buffer <= 0 {
		buffer = 16
	}
	ch := make(chan LedgerEntry, buffer)
	m.subMu.Lock()
	id := m.nextSubID
	m.nextSubID++
	m.subscribers[id] = ch
	m.subMu.Unlock()
	cancel := func() {
		m.subMu.Lock()
		if c, ok := m.subscribers[id]; ok {
			delete(m.subscribers, id)
			close(c)
		}
		m.subMu.Unlock()
	}
	return ch, cancel
}

// broadcast holds subMu for the duration of the fanout so a subscriber
// cancel — which also holds subMu to delete+close the channel — cannot
// overlap with an in-flight send. Sends are non-blocking, so holding
// the lock doesn't backpressure the writer.
func (m *Memory) broadcast(entry LedgerEntry) {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	for _, c := range m.subscribers {
		select {
		case c <- entry:
		default:
			// slow subscriber; drop rather than block
		}
	}
}

// resumeFromFile scans the JSONL ledger (if any) and returns the next seq
// to assign + the prev_leaf to chain from. Empty / missing file → zeros.
// A malformed last line is treated as fatal — better to crashloop than
// silently break the chain.
func resumeFromFile(path string) (uint64, [32]byte, error) {
	var zero [32]byte
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, zero, nil
		}
		return 0, zero, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Entries are small JSON blobs; bump buffer to be safe.
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	var lastSeq uint64
	var lastLeaf [32]byte
	lineCount := 0
	for sc.Scan() {
		lineCount++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry LedgerEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return 0, zero, fmt.Errorf("line %d: %w", lineCount, err)
		}
		raw, err := hex.DecodeString(entry.LeafHashHex)
		if err != nil || len(raw) != 32 {
			return 0, zero, fmt.Errorf("line %d: leaf_hash: %v", lineCount, err)
		}
		copy(lastLeaf[:], raw)
		lastSeq = entry.Seq
	}
	if err := sc.Err(); err != nil {
		return 0, zero, err
	}
	if lineCount == 0 {
		return 0, zero, nil
	}
	return lastSeq + 1, lastLeaf, nil
}

func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ledgerFile != nil {
		err := m.ledgerFile.Close()
		m.ledgerFile = nil
		return err
	}
	return nil
}

func (m *Memory) Health(_ context.Context) error { return nil }

func (m *Memory) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[s.ID]; exists {
		return ErrSessionExists
	}
	m.sessions[s.ID] = s
	return nil
}

func (m *Memory) GetSession(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

func (m *Memory) UpdateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[s.ID]; !ok {
		return ErrSessionNotFound
	}
	if _, ended := m.endedSess[s.ID]; ended {
		return ErrSessionEnded
	}
	m.sessions[s.ID] = s
	return nil
}

func (m *Memory) EndSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return ErrSessionNotFound
	}
	if _, ended := m.endedSess[id]; ended {
		return ErrSessionEnded
	}
	m.endedSess[id] = struct{}{}
	return nil
}

func (m *Memory) IsSessionActive(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return false, ErrSessionNotFound
	}
	if _, ended := m.endedSess[id]; ended {
		return false, nil
	}
	return true, nil
}

func (m *Memory) ListSessions(_ context.Context) ([]SessionView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SessionView, 0, len(m.sessions))
	for id, sess := range m.sessions {
		_, ended := m.endedSess[id]
		out = append(out, SessionView{Session: sess, Active: !ended})
	}
	return out, nil
}

func (m *Memory) ListLedger(_ context.Context) ([]LedgerEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := filepath.Join(m.home, "ledger.jsonl")
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []LedgerEntry
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e LedgerEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		// Rehydrate binary LeafHash / PrevLeaf from their hex twins so
		// callers get both forms consistently.
		if raw, err := hex.DecodeString(e.LeafHashHex); err == nil && len(raw) == 32 {
			copy(e.LeafHash[:], raw)
		}
		if raw, err := hex.DecodeString(e.PrevLeafHex); err == nil && len(raw) == 32 {
			copy(e.PrevLeaf[:], raw)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func (m *Memory) AppendLedger(_ context.Context, in AppendInput) (LedgerEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	leaf := ledger.LeafHash(in.PayloadHash, in.Sig, m.lastLeaf[:])
	entry := LedgerEntry{
		Seq:          m.nextSeq,
		TS:           in.TS,
		Source:       in.Source,
		ToolUseID:    in.ToolUseID,
		Tool:         in.Tool,
		Signer:       in.Signer,
		Input:        in.MatcherInput,
		RuleID:       in.RuleID,
		Verdict:      in.Verdict,
		MonitorMatch: in.MonitorMatch,
		PolicyTrace:  append([]PolicyTraceItem(nil), in.PolicyTrace...),
		PayloadHash:  hex.EncodeToString(in.PayloadHash),
		Sig:          hex.EncodeToString(in.Sig),
		LeafHash:     leaf,
		PrevLeaf:     m.lastLeaf,
		LeafHashHex:  hex.EncodeToString(leaf[:]),
		PrevLeafHex:  hex.EncodeToString(m.lastLeaf[:]),
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return LedgerEntry{}, fmt.Errorf("marshal ledger entry: %w", err)
	}
	if _, err := m.ledgerFile.Write(append(line, '\n')); err != nil {
		return LedgerEntry{}, fmt.Errorf("write ledger: %w", err)
	}
	if err := m.ledgerFile.Sync(); err != nil {
		return LedgerEntry{}, fmt.Errorf("sync ledger: %w", err)
	}

	m.nextSeq++
	m.lastLeaf = leaf
	// Fan out to SSE subscribers. Done under the main mutex release to
	// avoid holding both locks; subscriber sends are non-blocking anyway.
	go m.broadcast(entry)
	return entry, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
