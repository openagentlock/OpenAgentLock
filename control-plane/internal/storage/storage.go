// Storage interface. Backed by JSONL files under $AGENTLOCK_HOME today;
// could be SQLite later. Defined as an interface so the in-memory variant
// can drive tests without touching disk.

package storage

import "context"

type Storage interface {
	Health(ctx context.Context) error
	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, id string) (Session, error)
	UpdateSession(ctx context.Context, s Session) error
	EndSession(ctx context.Context, id string) error
	IsSessionActive(ctx context.Context, id string) (bool, error)
	ListSessions(ctx context.Context) ([]SessionView, error)
	AppendLedger(ctx context.Context, in AppendInput) (LedgerEntry, error)
	// ListLedger returns every entry in write order. Today this re-reads
	// ledger.jsonl from disk; a future SQLite backend would query a table.
	ListLedger(ctx context.Context) ([]LedgerEntry, error)
	// Subscribe returns a channel that receives every ledger entry written
	// after subscription. Caller invokes the returned cancel to release.
	Subscribe(buffer int) (<-chan LedgerEntry, func())
	// SaveDetections replaces the detection set reported for the session.
	SaveDetections(ctx context.Context, sessionID string, dets []Detection) error
	GetDetections(ctx context.Context, sessionID string) ([]Detection, error)
}

type Detection struct {
	Harness   string   `json:"harness"`
	Installed bool     `json:"installed"`
	Paths     []string `json:"paths"`
	Surfaces  []string `json:"surfaces"`
}

// SessionView is the denormalized session shape consumed by the dashboard
// and CLI listing commands. It's a projection of Session plus an Active
// flag that callers would otherwise derive with a separate IsSessionActive
// lookup.
type SessionView struct {
	Session
	Active bool `json:"active"`
}
