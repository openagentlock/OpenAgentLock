package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLedgerTail_SSEStreamsNewEntries(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", fx.srv.URL+"/v1/ledger/tail", nil)
	req.Header.Set("Accept", "text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET tail: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}

	// Kick the store: one gate.check produces one new leaf → one SSE event.
	body := fmt.Sprintf(`{"session_id":%q,"source":"claude-code","tool":"Bash","input":{"command":"ls"}}`, fx.sessionID)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = http.Post(fx.srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
	}()

	// The stream first replays the session.create entry, then streams the
	// fresh gate.check. Walk events until we see gate.check or the ctx
	// deadline trips the scanner.
	sc := bufio.NewScanner(res.Body)
	sawGate := false
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var entry map[string]any
		if err := json.Unmarshal([]byte(payload), &entry); err != nil {
			continue
		}
		if entry["tool_use_id"] == "gate.check" {
			sawGate = true
			break
		}
	}
	if !sawGate {
		t.Fatalf("SSE stream didn't deliver a gate.check event before deadline")
	}
}

func TestLedgerTail_IncludesExistingEntriesOnConnect(t *testing.T) {
	home := t.TempDir()
	store := mustNewMemoryStore(t, home)
	srv := httptest.NewServer(NewRouter(Deps{Store: store}))
	defer srv.Close()

	// Seed one entry before any subscriber connects.
	_, err := store.AppendLedger(context.Background(), storageAppendFixture())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v1/ledger/tail", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()

	sc := bufio.NewScanner(res.Body)
	got := ""
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data:") {
			got = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			break
		}
	}
	if got == "" {
		t.Fatal("expected replayed entry on connect")
	}
}
