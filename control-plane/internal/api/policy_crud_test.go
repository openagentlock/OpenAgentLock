// Tests for the policy CRUD HTTP surface. Today this covers the
// rules-registry-driven YAML install path (POST /v1/policy/gates/yaml);
// the simpler JSON add/patch/delete handlers ride on the same
// mutatePolicy plumbing and are exercised end-to-end by the higher-level
// gate / session lifecycle suites.

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

const seedPolicyYAML = `
version: 1
mode: monitor
defaults:
  bash: allow
gates:
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+-rf\b'
    evaluate:
      - kind: always
        action: deny
`

func newPolicyCRUDFixture(t *testing.T) *httptest.Server {
	t.Helper()
	pol, err := policy.LoadBytes([]byte(seedPolicyYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	home := t.TempDir()
	store, err := storage.NewMemory(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	bootstrapPolicy(pol)
	srv := httptest.NewServer(NewRouter(Deps{Store: store, Policy: pol, AgentlockHome: home}))
	t.Cleanup(srv.Close)
	return srv
}

func postPolicyJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	res, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return res
}

func TestPolicyAddGateYAML_Append(t *testing.T) {
	srv := newPolicyCRUDFixture(t)

	body := map[string]string{
		"yaml": `id: exfil.curl-with-env
match:
  tool: Bash
  any_command_regex:
    - 'curl[^|;&]*\$[A-Z_]+'
evaluate:
  - kind: always
    action: deny
`,
	}
	res := postPolicyJSON(t, srv.URL+"/v1/policy/gates/yaml", body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d, want 201", res.StatusCode)
	}
	var resp map[string]any
	_ = json.NewDecoder(res.Body).Decode(&resp)
	if resp["id"] != "exfil.curl-with-env" {
		t.Errorf("response id = %v, want exfil.curl-with-env", resp["id"])
	}
	if resp["needs_reload"] != true {
		t.Errorf("needs_reload should be true: %v", resp)
	}

	// /v1/policy/view should now include the new gate.
	view, err := http.Get(srv.URL + "/v1/policy/view")
	if err != nil {
		t.Fatalf("GET policy/view: %v", err)
	}
	defer view.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(view.Body)
	if !strings.Contains(buf.String(), "exfil.curl-with-env") {
		t.Errorf("policy view missing new gate; got %s", buf.String())
	}
}

func TestPolicyAddGateYAML_DuplicateRejected(t *testing.T) {
	srv := newPolicyCRUDFixture(t)
	body := map[string]string{
		"yaml": `id: rogue.destructive-bash
match:
  tool: Bash
evaluate:
  - kind: always
    action: deny
`,
	}
	res := postPolicyJSON(t, srv.URL+"/v1/policy/gates/yaml", body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (duplicate id)", res.StatusCode)
	}
}

func TestPolicyAddGateYAML_ReplaceOverwrites(t *testing.T) {
	srv := newPolicyCRUDFixture(t)
	body := map[string]any{
		"replace": true,
		"yaml": `id: rogue.destructive-bash
match:
  tool: Bash
  any_command_regex:
    - 'sudo\s+'
evaluate:
  - kind: always
    action: deny
`,
	}
	res := postPolicyJSON(t, srv.URL+"/v1/policy/gates/yaml", body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Errorf("status=%d, want 201 (replace)", res.StatusCode)
	}

	// Confirm the regex was rewritten.
	view, _ := http.Get(srv.URL + "/v1/policy/view")
	defer view.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(view.Body)
	if !strings.Contains(buf.String(), "sudo") {
		t.Errorf("expected updated regex 'sudo' in policy view; got %s", buf.String())
	}
}

func TestPolicyAddGateYAML_EmptyBody(t *testing.T) {
	srv := newPolicyCRUDFixture(t)
	res := postPolicyJSON(t, srv.URL+"/v1/policy/gates/yaml", map[string]string{"yaml": "   "})
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (empty yaml)", res.StatusCode)
	}
}

func TestPolicyAddGateYAML_MalformedYAML(t *testing.T) {
	srv := newPolicyCRUDFixture(t)
	res := postPolicyJSON(t, srv.URL+"/v1/policy/gates/yaml", map[string]string{
		"yaml": "id: rogue.destructive-bash\nmatch: [unclosed",
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (malformed yaml)", res.StatusCode)
	}
}
