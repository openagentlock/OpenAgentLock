package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const insightsPolicyYAML = `
version: 1
mode: enforce
gates:
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex: ['rm\s+-rf\b']
    evaluate:
      - kind: always
        action: deny
  - id: rogue.secret-read
    match:
      any_of:
        - { tool: Read, path_glob: "**/.env*" }
    evaluate:
      - kind: always
        action: deny
`

func TestInsights_Aggregates(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)

	// Fire a mix of verdicts against the live policy.
	type call struct {
		tool, cmd string
	}
	calls := []call{
		{"Bash", "ls -la"},              // allow default
		{"Bash", "ls -la"},              // allow default
		{"Bash", "rm -rf /tmp/x"},       // deny destructive-bash
		{"Read", "/home/alice/.env"},    // deny secret-read (via file_path)
	}
	for _, c := range calls {
		if c.tool == "Read" {
			body := fmt.Sprintf(`{"session_id":%q,"source":"claude-code","tool":"Read","input":{"file_path":%q}}`, fx.sessionID, c.cmd)
			_, _ = http.Post(fx.srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
			continue
		}
		body := fmt.Sprintf(`{"session_id":%q,"source":"claude-code","tool":%q,"input":{"command":%q}}`, fx.sessionID, c.tool, c.cmd)
		_, _ = http.Post(fx.srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
	}

	res, err := http.Get(fx.srv.URL + "/v1/sessions/" + fx.sessionID + "/insights")
	if err != nil {
		t.Fatalf("GET insights: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["session_id"] != fx.sessionID {
		t.Fatalf("session_id echo: %v", out["session_id"])
	}
	counts, _ := out["counts"].(map[string]any)
	if counts == nil {
		t.Fatalf("counts missing: %+v", out)
	}
	byRule, _ := counts["by_rule"].(map[string]any)
	if byRule["rogue.destructive-bash"] == nil {
		t.Fatalf("expected destructive-bash count: %+v", byRule)
	}
	if byRule["rogue.secret-read"] == nil {
		t.Fatalf("expected secret-read count: %+v", byRule)
	}
	bySource, _ := counts["by_source"].(map[string]any)
	if bySource["claude-code"] == nil {
		t.Fatalf("expected claude-code count: %+v", bySource)
	}
}

func TestInsights_UnknownSession_Returns404(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	res, err := http.Get(fx.srv.URL + "/v1/sessions/does-not-exist/insights")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

// fireGateChecks runs a small mix of allow + deny calls so the ledger
// has something to aggregate. Returns nothing — failures here are non-
// fatal because the goal is just to seed the ledger.
func fireGateChecks(fx gateFixture) {
	calls := []struct {
		tool, cmd string
	}{
		{"Bash", "ls -la"},
		{"Bash", "ls -la"},
		{"Bash", "ls -la"},
		{"Bash", "rm -rf /tmp/x"},
		{"Bash", "rm -rf /var/log"},
		{"Read", "/home/alice/.env"},
	}
	for _, c := range calls {
		var body string
		if c.tool == "Read" {
			body = fmt.Sprintf(`{"session_id":%q,"source":"claude-code","tool":"Read","input":{"file_path":%q}}`, fx.sessionID, c.cmd)
		} else {
			body = fmt.Sprintf(`{"session_id":%q,"source":"claude-code","tool":%q,"input":{"command":%q}}`, fx.sessionID, c.tool, c.cmd)
		}
		_, _ = http.Post(fx.srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
	}
}

func TestLedgerInsights_DefaultWindow(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	fireGateChecks(fx)

	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights")
	if err != nil {
		t.Fatalf("GET insights: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["window"] != "24h" {
		t.Fatalf("default window: %v", out["window"])
	}
	totalF, _ := out["total"].(float64)
	if totalF == 0 {
		t.Fatalf("expected non-zero total, got %+v", out)
	}
	byVerdict, _ := out["by_verdict"].(map[string]any)
	if byVerdict["allow"] == nil || byVerdict["deny"] == nil {
		t.Fatalf("expected allow+deny in by_verdict: %+v", byVerdict)
	}
	topRules, _ := out["top_rules_deny"].([]any)
	if len(topRules) == 0 {
		t.Fatalf("expected at least one top deny rule: %+v", out)
	}
	first, _ := topRules[0].(map[string]any)
	if first["key"] != "rogue.destructive-bash" && first["key"] != "rogue.secret-read" {
		t.Fatalf("unexpected top rule: %+v", first)
	}
	buckets, _ := out["buckets"].([]any)
	if len(buckets) != 24 {
		t.Fatalf("24h window should have 24 hourly buckets, got %d", len(buckets))
	}
}

func TestLedgerInsights_OneHourWindow(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	fireGateChecks(fx)

	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights?window=1h&top=2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["window"] != "1h" {
		t.Fatalf("window: %v", out["window"])
	}
	buckets, _ := out["buckets"].([]any)
	if len(buckets) != 12 {
		t.Fatalf("1h window should have 12 5min buckets, got %d", len(buckets))
	}
	topRules, _ := out["top_rules_deny"].([]any)
	if len(topRules) > 2 {
		t.Fatalf("top=2 should cap at 2, got %d", len(topRules))
	}
}

func TestLedgerInsights_SevenDayWindow(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	fireGateChecks(fx)

	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights?window=7d")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["window"] != "7d" {
		t.Fatalf("window: %v", out["window"])
	}
	buckets, _ := out["buckets"].([]any)
	if len(buckets) != 7 {
		t.Fatalf("7d window should have 7 daily buckets, got %d", len(buckets))
	}
	bs, _ := out["bucket_seconds"].(float64)
	if int(bs) != 86400 {
		t.Fatalf("7d bucket_seconds should be 86400 (1 day), got %v", bs)
	}
}

func TestLedgerInsights_AllWindow(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	fireGateChecks(fx)

	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights?window=all")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["window"] != "all" {
		t.Fatalf("window: %v", out["window"])
	}
	buckets, _ := out["buckets"].([]any)
	if len(buckets) != 0 {
		t.Fatalf("all window should have no buckets, got %d", len(buckets))
	}
}

func TestLedgerInsights_BadWindow_Returns400(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights?window=bogus")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestLedgerInsights_BadTop_Returns400(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights?top=999")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestLedgerInsights_EmptyLedger(t *testing.T) {
	fx := newGateFixture(t, insightsPolicyYAML)
	res, err := http.Get(fx.srv.URL + "/v1/ledger/insights")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	// Session-create traffic produces a few entries; total should still
	// decode and equal the count of entries in the ledger.
	if _, ok := out["total"].(float64); !ok {
		t.Fatalf("total missing from empty-ish payload: %+v", out)
	}
	buckets, _ := out["buckets"].([]any)
	if len(buckets) != 24 {
		t.Fatalf("expected 24 buckets even when empty: got %d", len(buckets))
	}
}
