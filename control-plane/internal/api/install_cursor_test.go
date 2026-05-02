package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cursorApplyBody(fx gateFixture, dir, binary string) string {
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["cursor"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": %q
	}`, fx.sessionID, dir, binary)
}

func postCursorApply(t *testing.T, fx gateFixture, dir, binary string) *http.Response {
	t.Helper()
	res, err := http.Post(
		fx.srv.URL+"/v1/install/apply",
		"application/json",
		strings.NewReader(cursorApplyBody(fx, dir, binary)),
	)
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

func TestInstallPlan_CursorProducesWriteOp(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["cursor"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": "/usr/local/bin/agentlock"
	}`, fx.sessionID, dir)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var plan map[string]any
	_ = json.NewDecoder(res.Body).Decode(&plan)
	ops, _ := plan["operations"].([]any)
	if len(ops) == 0 {
		t.Fatalf("expected ops: %+v", plan)
	}
	op, _ := ops[0].(map[string]any)
	path, _ := op["path"].(string)
	if !strings.HasSuffix(path, "hooks.json") {
		t.Fatalf("expected hooks.json path, got %q", path)
	}
	content, _ := op["content"].(string)
	for _, want := range []string{
		`"version": 1`,
		`"preToolUse"`,
		`"sessionStart"`,
		`"beforeMCPExecution"`,
		`"afterMCPExecution"`,
		`"postToolUse"`,
		`"sessionEnd"`,
		`/usr/local/bin/agentlock hook cursor pre-tool-use`,
		`"AGENTLOCK_DAEMON_URL": "http://127.0.0.1:7878"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("missing %q in plan content: %s", want, content)
		}
	}
	// Cursor has no flag-gate caveat, so warnings should be empty.
	warns, _ := plan["warnings"].([]any)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings for cursor plan: %v", warns)
	}
}

func TestInstallApply_CursorWritesHooksJson(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	res := postCursorApply(t, fx, dir, "/usr/local/bin/agentlock")
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var out installApplyResponse
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}

	hooksPath := filepath.Join(dir, "hooks.json")
	b, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatalf("read hooks.json: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"_agentlock"`,
		`"version": 1`,
		`"preToolUse"`,
		`"sessionStart"`,
		`"beforeShellExecution"`,
		`"beforeMCPExecution"`,
		`"afterMCPExecution"`,
		`"postToolUse"`,
		`"sessionEnd"`,
		`"type": "command"`,
		`/usr/local/bin/agentlock hook cursor pre-tool-use`,
		`"AGENTLOCK_DAEMON_URL"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in hooks.json: %s", want, s)
		}
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "install.apply" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing install.apply ledger entry: %+v", entries)
	}
}

func TestInstallApply_CursorPreservesExistingUserHooks(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	user := `{
		"hooks": {
			"preToolUse": [
				{"matcher": "*", "hooks": [{"type": "command", "command": "user-hook.sh"}]}
			]
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res := postCursorApply(t, fx, dir, "/usr/local/bin/agentlock")
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	s := string(b)
	if !strings.Contains(s, "user-hook.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if !strings.Contains(s, "_agentlock") {
		t.Fatalf("our entry missing: %s", s)
	}
}

func TestInstallApply_CursorPreservesVersionField(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	// User had set their own top-level version; we must not stomp it.
	user := `{"version": 2, "hooks": {}}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res := postCursorApply(t, fx, dir, "/usr/local/bin/agentlock")
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, _ := parsed["version"].(float64)
	if int(got) != 2 {
		t.Fatalf("user version field lost: got %v, want 2; full: %s", parsed["version"], b)
	}
}

func TestInstallApply_CursorIdempotent(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	_ = postCursorApply(t, fx, dir, "/usr/local/bin/agentlock").Body.Close()
	_ = postCursorApply(t, fx, dir, "/usr/local/bin/agentlock").Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	got := strings.Count(string(b), `"_agentlock"`)
	// 7 events wired (sessionStart + preToolUse + beforeShellExecution +
	// beforeMCPExecution + afterMCPExecution + postToolUse + sessionEnd).
	// Re-applying must replace, not duplicate.
	if got != 7 {
		t.Fatalf("expected 7 _agentlock entries, got %d: %s", got, b)
	}
}

func TestInstallUninstall_CursorStripsOurEntriesOnly(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	user := `{"version":1,"hooks":{"preToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_ = postCursorApply(t, fx, dir, "/usr/local/bin/agentlock").Body.Close()
	res := postUninstall(t, fx, fx.sessionID)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	s := string(b)
	if !strings.Contains(s, "mine.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if strings.Contains(s, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", s)
	}
	if strings.Contains(s, "agentlock hook cursor") {
		t.Fatalf("our shim invocation should be gone: %s", s)
	}
	// The user's original version field still survives.
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("parse final: %v", err)
	}
	if v, _ := parsed["version"].(float64); int(v) != 1 {
		t.Fatalf("user version = %v, want 1", parsed["version"])
	}
}

func TestInstallApply_CursorRefusesRealHome(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	home, _ := os.UserHomeDir()
	if home == "" {
		t.Skip("no home")
	}
	res := postCursorApply(t, fx, filepath.Join(home, ".cursor"), "/usr/local/bin/agentlock")
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body["error"] != "unsafe_target" {
		t.Fatalf("error = %v", body["error"])
	}
}
