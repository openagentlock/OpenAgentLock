package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ledgerTailHandler emits every existing ledger entry on connect and then
// streams new entries as they land. Uses Server-Sent Events so browsers
// and curl speak it without a WebSocket upgrade. Keepalive comment every
// 30s to keep intermediaries from timing the connection out.
func ledgerTailHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("ledger.tail")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "streaming_unsupported", "")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		// Subscribe before the replay so nothing appended in between is dropped.
		ch, cancel := d.Store.Subscribe(32)
		defer cancel()

		// Replay existing entries so the client can pick up from 0 on reconnect.
		entries, err := d.Store.ListLedger(r.Context())
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonString(map[string]string{
				"error":  "ledger_replay_failed",
				"detail": err.Error(),
			}))
			flusher.Flush()
			return
		}
		for _, e := range entries {
			writeSSEEvent(w, flusher, e)
		}

		ctx, cctx := context.WithCancel(r.Context())
		defer cctx()
		keep := time.NewTicker(30 * time.Second)
		defer keep.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case entry, open := <-ch:
				if !open {
					return
				}
				writeSSEEvent(w, flusher, entry)
			case <-keep.C:
				fmt.Fprintf(w, ": keepalive\n\n")
				flusher.Flush()
			}
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, f http.Flusher, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
