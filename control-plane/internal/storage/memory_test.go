package storage

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Memory, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewMemory(dir)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	return s, dir
}

func fixtureSession() Session {
	now := time.Unix(1_700_000_000, 0).UTC()
	return Session{
		ID:            "01JWXYZABCDEFG",
		StartedAt:     now,
		ExpiresAt:     now.Add(4 * time.Hour),
		PolicyHash:    "sha256:aa",
		SessionPubKey: "ed25519:bb",
		Signer:        "software",
		SignerPubKey:  "ed25519:cc",
	}
}

func fixtureAppend() AppendInput {
	return AppendInput{
		TS:          time.Unix(1_700_000_000, 0).UTC(),
		Source:      "system",
		ToolUseID:   "session.create",
		Signer:      "software",
		PayloadHash: []byte("payload-hash-fixture"),
		Sig:         []byte("signature-fixture"),
	}
}

func TestMemory_CreateAndGetSession(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess := fixtureSession()

	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sess.ID || got.PolicyHash != sess.PolicyHash {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestMemory_CreateSession_DuplicateRejected(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess := fixtureSession()

	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("first CreateSession: %v", err)
	}
	err := s.CreateSession(ctx, sess)
	if !errors.Is(err, ErrSessionExists) {
		t.Fatalf("expected ErrSessionExists, got %v", err)
	}
}

func TestMemory_GetSession_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	_, err := s.GetSession(ctx, "does-not-exist")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestMemory_AppendLedger_SeqIsMonotonic(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	in := fixtureAppend()

	first, err := s.AppendLedger(ctx, in)
	if err != nil {
		t.Fatalf("first AppendLedger: %v", err)
	}
	if first.Seq != 0 {
		t.Fatalf("first seq = %d, want 0", first.Seq)
	}
	if first.PrevLeaf != ([32]byte{}) {
		t.Fatalf("first prev_leaf must be zero, got %x", first.PrevLeaf)
	}

	second, err := s.AppendLedger(ctx, in)
	if err != nil {
		t.Fatalf("second AppendLedger: %v", err)
	}
	if second.Seq != 1 {
		t.Fatalf("second seq = %d, want 1", second.Seq)
	}
	if second.PrevLeaf != first.LeafHash {
		t.Fatalf("second prev_leaf must equal first leaf_hash\n want: %x\n  got: %x", first.LeafHash, second.PrevLeaf)
	}
	if second.LeafHash == first.LeafHash {
		t.Fatal("second leaf_hash must differ from first")
	}
}

func TestMemory_AppendLedger_WritesJsonLFile(t *testing.T) {
	s, dir := newTestStore(t)
	ctx := context.Background()

	if _, err := s.AppendLedger(ctx, fixtureAppend()); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	if _, err := s.AppendLedger(ctx, fixtureAppend()); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}

	f, err := os.Open(filepath.Join(dir, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open ledger.jsonl: %v", err)
	}
	defer f.Close()

	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if !strings.HasPrefix(sc.Text(), `{`) {
			t.Fatalf("non-JSON line: %q", sc.Text())
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("want 2 ledger lines, got %d", lines)
	}
}

func TestMemory_ResumesChainAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// First boot: append two entries.
	s1, err := NewMemory(dir)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	first, err := s1.AppendLedger(ctx, fixtureAppend())
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	second, err := s1.AppendLedger(ctx, fixtureAppend())
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second boot: must resume seq + prev_leaf, not start from zero.
	s2, err := NewMemory(dir)
	if err != nil {
		t.Fatalf("NewMemory (resume): %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	third, err := s2.AppendLedger(ctx, fixtureAppend())
	if err != nil {
		t.Fatalf("append 3: %v", err)
	}
	if third.Seq != 2 {
		t.Fatalf("third seq = %d, want 2 (resumed)", third.Seq)
	}
	if third.PrevLeaf != second.LeafHash {
		t.Fatalf("third prev_leaf must chain from second leaf_hash\n want: %x\n  got: %x",
			second.LeafHash, third.PrevLeaf)
	}
	if third.LeafHash == second.LeafHash {
		t.Fatal("third leaf_hash must differ from second")
	}
	_ = first // silence unused if reader compresses
}

func TestMemory_BroadcastRaceDoesNotPanic(t *testing.T) {
	// Exercises the subscribe/cancel + append race: without the recover
	// in trySend, a cancel that closes a subscriber channel concurrently
	// with a broadcast would panic "send on closed channel".
	s, _ := newTestStore(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Subscribers that open then cancel in a tight loop.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, cancel := s.Subscribe(1)
				// Keep the window short so cancel often lands during a
				// broadcast goroutine's non-blocking send.
				time.Sleep(time.Microsecond)
				cancel()
			}
		}()
	}

	// Writers that trigger broadcast over and over.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, err := s.AppendLedger(ctx, fixtureAppend()); err != nil {
					t.Errorf("AppendLedger: %v", err)
					return
				}
			}
		}()
	}

	// Let the writers finish, then stop the subscribers.
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()
}

func TestMemory_LedgerFileCreatedMode0600(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("file-mode check does not apply on Windows")
	}
	s, dir := newTestStore(t)
	ctx := context.Background()
	if _, err := s.AppendLedger(ctx, fixtureAppend()); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("ledger.jsonl mode = %v, want 0600", st.Mode().Perm())
	}
}
