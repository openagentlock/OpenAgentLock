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
