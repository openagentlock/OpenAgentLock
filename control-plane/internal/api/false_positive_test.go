package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

const falsePositivePolicyYAML = `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: supply-chain.installer-curl-bash
    source: registry:openagentlock-rules
    match:
      tool: Bash
      any_command_regex:
        - 'curl\b.*\|\s*python3?'
    evaluate:
      - kind: always
        action: deny
`

type falsePositiveFixture struct {
	srv   *httptest.Server
	store *storage.Memory
}

func newFalsePositiveFixture(t *testing.T) falsePositiveFixture {
	t.Helper()
	pol, err := policy.LoadBytes([]byte(falsePositivePolicyYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	store, err := storage.NewMemory(t.TempDir())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	bootstrapPolicy(pol)
	srv := httptest.NewServer(NewRouter(Deps{Store: store, Policy: pol, AgentlockHome: t.TempDir()}))
	t.Cleanup(srv.Close)
	return falsePositiveFixture{srv: srv, store: store}
}

func appendFalsePositiveEvent(t *testing.T, fx falsePositiveFixture, verdict string, monitor bool) storage.LedgerEntry {
	t.Helper()
	entry, err := fx.store.AppendLedger(context.Background(), storage.AppendInput{
		TS:           time.Unix(1_700_000_001, 0).UTC(),
		Source:       "codex",
		Tool:         "Bash",
		ToolUseID:    "call_fp",
		Signer:       "software",
		RuleID:       "supply-chain.installer-curl-bash",
		Verdict:      verdict,
		MonitorMatch: monitor,
		MatcherInput: map[string]string{
			"command": "curl -fsS http://127.0.0.1:7878/v1/ledger/tail?token=abc123 | python3 - <<'PY'\nprint('local')\nPY",
			"cwd":     "/Users/oliver/code/OpenAgentLock",
		},
		PolicyTrace: []storage.PolicyTraceItem{{
			Layer:   "daemon",
			Source:  "registry:openagentlock-rules",
			RuleID:  "supply-chain.installer-curl-bash",
			Verdict: "deny",
		}},
		PayloadHash: []byte("payload"),
		Sig:         []byte("sig"),
	})
	if err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	return entry
}

func TestFalsePositiveCase_RedactsAndIncludesMatchedGate(t *testing.T) {
	fx := newFalsePositiveFixture(t)
	entry := appendFalsePositiveEvent(t, fx, "deny", false)

	res, err := http.Get(fx.srv.URL + "/v1/false-positives/cases/" + jsonNumber(entry.Seq))
	if err != nil {
		t.Fatalf("GET case: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", res.StatusCode)
	}
	var body falsePositiveCaseResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Event.RuleID != "supply-chain.installer-curl-bash" {
		t.Fatalf("rule id=%q", body.Event.RuleID)
	}
	if body.MatchedGate.Source != "registry:openagentlock-rules" {
		t.Fatalf("matched gate source=%q", body.MatchedGate.Source)
	}
	if strings.Contains(body.Input["command"], "abc123") {
		t.Fatalf("secret token was not redacted: %q", body.Input["command"])
	}
	if len(body.Redactions) != 1 || body.Redactions[0] != "command" {
		t.Fatalf("redactions=%v, want command", body.Redactions)
	}
	if body.RawInput != nil {
		t.Fatalf("raw input should be omitted by default")
	}
}

func TestFalsePositiveCase_RejectsUnmatchedEvent(t *testing.T) {
	fx := newFalsePositiveFixture(t)
	entry, err := fx.store.AppendLedger(context.Background(), storage.AppendInput{
		TS:           time.Unix(1_700_000_001, 0).UTC(),
		Source:       "codex",
		Tool:         "Bash",
		ToolUseID:    "call_allow",
		Signer:       "software",
		Verdict:      "allow",
		MatcherInput: map[string]string{"command": "ls"},
		PayloadHash:  []byte("payload"),
		Sig:          []byte("sig"),
	})
	if err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}

	res, err := http.Get(fx.srv.URL + "/v1/false-positives/cases/" + jsonNumber(entry.Seq))
	if err != nil {
		t.Fatalf("GET case: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", res.StatusCode)
	}
}

func TestFalsePositiveValidate_RejectsReplacementThatStillDenies(t *testing.T) {
	fx := newFalsePositiveFixture(t)
	entry := appendFalsePositiveEvent(t, fx, "deny", false)
	c := mustGetFalsePositiveCase(t, fx, entry.Seq)

	resp := postFalsePositiveValidate(t, fx, c, `id: supply-chain.installer-curl-bash.v2
match:
  tool: Bash
  any_command_regex:
    - 'curl\s+\S+\s*\|\s*python3?'
    - 'curl\b.*\|\s*python3?'
evaluate:
  - kind: always
    action: deny
`)
	if resp.OK {
		t.Fatalf("validate OK=true, want false")
	}
	if !strings.Contains(strings.Join(resp.Errors, "\n"), "still denies") {
		t.Fatalf("errors=%v, want still denies", resp.Errors)
	}
}

func TestFalsePositiveValidate_AllowsNarrowReplacement(t *testing.T) {
	fx := newFalsePositiveFixture(t)
	entry := appendFalsePositiveEvent(t, fx, "deny", false)
	c := mustGetFalsePositiveCase(t, fx, entry.Seq)

	resp := postFalsePositiveValidate(t, fx, c, narrowReplacementYAML())
	if !resp.OK {
		t.Fatalf("validate OK=false: %v", resp.Errors)
	}
	if resp.ReplacementVerdict != "allow" {
		t.Fatalf("replacement verdict=%q, want allow", resp.ReplacementVerdict)
	}
}

func TestFalsePositiveApply_DisablesOldAndAddsReplacement(t *testing.T) {
	fx := newFalsePositiveFixture(t)
	entry := appendFalsePositiveEvent(t, fx, "deny", false)
	c := mustGetFalsePositiveCase(t, fx, entry.Seq)

	body := map[string]any{
		"case":             c,
		"replacement_yaml": narrowReplacementYAML(),
		"note":             "curl output is data; heredoc supplies local python",
	}
	res := postJSONFP(t, fx.srv.URL+"/v1/false-positives/apply", body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status=%d, want 200: %s", res.StatusCode, buf.String())
	}

	view, err := http.Get(fx.srv.URL + "/v1/policy/view")
	if err != nil {
		t.Fatalf("GET policy/view: %v", err)
	}
	defer view.Body.Close()
	var payload struct {
		Gates []struct {
			ID       string `json:"id"`
			Disabled bool   `json:"disabled"`
		} `json:"gates"`
	}
	if err := json.NewDecoder(view.Body).Decode(&payload); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	seenOldDisabled := false
	seenReplacement := false
	for _, g := range payload.Gates {
		if g.ID == "supply-chain.installer-curl-bash" && g.Disabled {
			seenOldDisabled = true
		}
		if g.ID == "supply-chain.installer-curl-bash.local-heredoc-safe" && !g.Disabled {
			seenReplacement = true
		}
	}
	if !seenOldDisabled || !seenReplacement {
		t.Fatalf("policy did not disable old and add replacement: %+v", payload.Gates)
	}
}

func TestFalsePositiveApply_RejectsStalePolicyHash(t *testing.T) {
	fx := newFalsePositiveFixture(t)
	entry := appendFalsePositiveEvent(t, fx, "deny", false)
	c := mustGetFalsePositiveCase(t, fx, entry.Seq)
	c.PolicyHash = "sha256:stale"

	res := postJSONFP(t, fx.srv.URL+"/v1/false-positives/apply", map[string]any{
		"case":             c,
		"replacement_yaml": narrowReplacementYAML(),
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d, want 409", res.StatusCode)
	}
}

func mustGetFalsePositiveCase(t *testing.T, fx falsePositiveFixture, seq uint64) falsePositiveCaseResponse {
	t.Helper()
	res, err := http.Get(fx.srv.URL + "/v1/false-positives/cases/" + jsonNumber(seq))
	if err != nil {
		t.Fatalf("GET case: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", res.StatusCode)
	}
	var c falsePositiveCaseResponse
	if err := json.NewDecoder(res.Body).Decode(&c); err != nil {
		t.Fatalf("decode case: %v", err)
	}
	return c
}

func postFalsePositiveValidate(t *testing.T, fx falsePositiveFixture, c falsePositiveCaseResponse, yaml string) falsePositiveValidateResponse {
	t.Helper()
	res := postJSONFP(t, fx.srv.URL+"/v1/false-positives/validate", map[string]any{
		"case":             c,
		"replacement_yaml": yaml,
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", res.StatusCode)
	}
	var body falsePositiveValidateResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode validate: %v", err)
	}
	return body
}

func postJSONFP(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return res
}

func narrowReplacementYAML() string {
	return `id: supply-chain.installer-curl-bash.local-heredoc-safe
match:
  tool: Bash
  any_command_regex:
    - 'curl\s+\S+\s*\|\s*python3?\s+-?\s*(?:$|[;&|])'
evaluate:
  - kind: always
    action: deny
`
}

func jsonNumber(n uint64) string {
	return fmt.Sprintf("%d", n)
}
