package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

// insightsHandler returns a per-session aggregate of the ledger: counts
// by rule_id, by source, by tool_use_id. The ledger entries don't carry
// rule_id directly (yet) — we extract it from tool_use_id for now and
// wire richer per-entry metadata in a later slice.
func insightsHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("insights")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := routeParam("/v1/sessions/{id}/insights", r.URL.Path, "id")
		if _, err := d.Store.GetSession(r.Context(), id); err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", id)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		entries, err := d.Store.ListLedger(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		byRule := map[string]int{}
		byVerdict := map[string]int{}
		bySource := map[string]int{}
		byTool := map[string]int{}
		total := 0
		for _, e := range entries {
			if e.RuleID != "" {
				byRule[e.RuleID]++
			}
			if e.Verdict != "" {
				byVerdict[e.Verdict]++
			}
			if e.Tool != "" {
				byTool[e.Tool]++
			}
			if e.Source != "" {
				bySource[e.Source]++
			}
			total++
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"session_id": id,
			"counts": map[string]any{
				"total":      total,
				"by_rule":    byRule,
				"by_verdict": byVerdict,
				"by_source":  bySource,
				"by_tool":    byTool,
			},
		})
	}
}

// ledgerInsightsHandler returns time-windowed aggregations over the
// global ledger: allow/deny totals, top-N deny rules and tools, source
// breakdown, and a coarse time-bucketed series for sparkline rendering.
//
// Query params:
//   window: 1h | 24h | 7d | all   (default 24h)
//   top:    integer 1..50         (default 5)
//
// The handler walks the entire ledger once per request. The CLI TUI
// polls this every ~5s; for terminal-volume traffic that's fine. When
// the ledger crosses ~1M entries we'll add bucketed indexes — until
// then a linear scan is the honest choice.
func ledgerInsightsHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("ledger.insights")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		window := r.URL.Query().Get("window")
		if window == "" {
			window = "24h"
		}
		dur, bucket, ok := windowParams(window)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_window",
				"window must be one of 1h, 24h, 7d, all")
			return
		}
		topN := 5
		if s := r.URL.Query().Get("top"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 50 {
				writeError(w, http.StatusBadRequest, "bad_top",
					"top must be an integer in [1, 50]")
				return
			}
			topN = n
		}

		entries, err := d.Store.ListLedger(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		now := time.Now().UTC()
		var since time.Time
		if dur > 0 {
			since = now.Add(-dur)
		}

		byVerdict := map[string]int{}
		bySource := map[string]int{}
		denyByRule := map[string]int{}
		denyByTool := map[string]int{}
		total := 0

		// Bucket layout: bucketCount evenly-sized slots ending at `now`.
		bucketCount := 0
		var bucketStart time.Time
		if dur > 0 && bucket > 0 {
			bucketCount = int(dur / bucket)
			bucketStart = now.Add(-time.Duration(bucketCount) * bucket)
		}
		allowB := make([]int, bucketCount)
		denyB := make([]int, bucketCount)

		for _, e := range entries {
			if dur > 0 && e.TS.Before(since) {
				continue
			}
			total++
			if e.Verdict != "" {
				byVerdict[e.Verdict]++
			}
			if e.Source != "" {
				bySource[e.Source]++
			}
			// MonitorMatch entries record the original deny pattern in
			// rule_id even though their verdict was forced to allow —
			// surface them as denies in the operational view so the
			// "what would have been blocked?" picture is honest.
			isDeny := e.Verdict == "deny" || e.MonitorMatch
			if isDeny && e.RuleID != "" {
				denyByRule[e.RuleID]++
			}
			if isDeny && e.Tool != "" {
				denyByTool[e.Tool]++
			}
			if bucketCount > 0 {
				idx := int(e.TS.Sub(bucketStart) / bucket)
				if idx < 0 {
					idx = 0
				}
				if idx >= bucketCount {
					idx = bucketCount - 1
				}
				if isDeny {
					denyB[idx]++
				} else {
					allowB[idx]++
				}
			}
		}

		buckets := make([]map[string]any, bucketCount)
		for i := 0; i < bucketCount; i++ {
			buckets[i] = map[string]any{
				"ts":    bucketStart.Add(time.Duration(i) * bucket).Format(time.RFC3339),
				"allow": allowB[i],
				"deny":  denyB[i],
			}
		}

		out := map[string]any{
			"window":          window,
			"now":             now.Format(time.RFC3339),
			"bucket_seconds":  int(bucket / time.Second),
			"total":           total,
			"by_verdict":      byVerdict,
			"by_source":       bySource,
			"top_rules_deny":  topNCounts(denyByRule, topN),
			"top_tools_deny":  topNCounts(denyByTool, topN),
			"buckets":         buckets,
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// windowParams maps a window label to (duration, bucketSize). bucket
// counts match the natural granularity humans use for each window: 1h
// reads in 5-minute slices, 24h in hourly bars, 7d in daily bars.
//
//	1h  → 12 × 5min
//	24h → 24 × 1h
//	7d  →  7 × 24h
//	all → no time filter, no buckets
func windowParams(w string) (time.Duration, time.Duration, bool) {
	switch w {
	case "1h":
		return time.Hour, 5 * time.Minute, true
	case "24h":
		return 24 * time.Hour, time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, 24 * time.Hour, true
	case "all":
		return 0, 0, true
	}
	return 0, 0, false
}

func topNCounts(m map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	out := make([]map[string]any, len(pairs))
	for i, p := range pairs {
		out[i] = map[string]any{"key": p.k, "count": p.v}
	}
	return out
}
