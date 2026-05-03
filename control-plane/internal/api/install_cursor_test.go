package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func cursorApplyBody(fx gateFixture, dir, binary string, existing map[string]string) string {
	if existing == nil {
		existing = map[string]string{}
	}
	ex, _ := json.Marshal(existing)
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["cursor"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": %q,
		"existing_files": %s
	}`, fx.sessionID, dir, binary, ex)
}

func postCursorApply(t *testing.T, fx gateFixture, dir, binary string, existing map[string]string) *http.Response {
	t.Helper()
	res, err := http.Post(
		fx.srv.URL+"/v1/install/apply",
		"application/json",
		strings.NewReader(cursorApplyBody(fx, dir, binary, existing)),
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

func TestInstallApply_CursorReturnsHooksContent(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	res := postCursorApply(t, fx, dir, "/usr/local/bin/agentlock", nil)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}
	op, ok := findOpByPath(out.Operations, "hooks.json")
	if !ok {
		t.Fatalf("no hooks.json op: %+v", out.Operations)
	}
	s := op.Content
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
			t.Fatalf("missing %q in hooks.json content: %s", want, s)
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
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	user := `{
		"hooks": {
			"preToolUse": [
				{"matcher": "*", "hooks": [{"type": "command", "command": "user-hook.sh"}]}
			]
		}
	}`
	res := postCursorApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		hooksPath: user,
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	op, _ := findOpByPath(out.Operations, "hooks.json")
	s := op.Content
	if !strings.Contains(s, "user-hook.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if !strings.Contains(s, "_agentlock") {
		t.Fatalf("our entry missing: %s", s)
	}
	if op.BackupPath == "" {
		t.Fatalf("expected backup_path on hooks op when existing file supplied")
	}
}

func TestInstallApply_CursorPreservesVersionField(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	// User had set their own top-level version; we must not stomp it.
	user := `{"version": 2, "hooks": {}}`
	res := postCursorApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		hooksPath: user,
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	op, _ := findOpByPath(out.Operations, "hooks.json")
	var parsed map[string]any
	if err := json.Unmarshal([]byte(op.Content), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, _ := parsed["version"].(float64)
	if int(got) != 2 {
		t.Fatalf("user version field lost: got %v, want 2; full: %s", parsed["version"], op.Content)
	}
}

func TestInstallApply_CursorIdempotent(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	first := decodeApplyResponse(t, postCursorApply(t, fx, dir, "/usr/local/bin/agentlock", nil))
	firstOp, _ := findOpByPath(first.Operations, "hooks.json")

	second := decodeApplyResponse(t, postCursorApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		hooksPath: firstOp.Content,
	}))
	secondOp, _ := findOpByPath(second.Operations, "hooks.json")
	got := strings.Count(secondOp.Content, `"_agentlock"`)
	// 7 events wired (sessionStart + preToolUse + beforeShellExecution +
	// beforeMCPExecution + afterMCPExecution + postToolUse + sessionEnd).
	// Re-applying must replace, not duplicate.
	if got != 7 {
		t.Fatalf("expected 7 _agentlock entries, got %d: %s", got, secondOp.Content)
	}
}

func TestInstallUninstall_CursorStripsOurEntriesOnly(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	user := `{"version":1,"hooks":{"preToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	applyOut := decodeApplyResponse(t, postCursorApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		hooksPath: user,
	}))
	mergedOp, _ := findOpByPath(applyOut.Operations, "hooks.json")

	res := postUninstallWithExisting(t, fx, fx.sessionID, map[string]string{
		hooksPath: mergedOp.Content,
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeUninstallResponse(t, res)
	var stripOp uninstallOp
	for _, op := range out.Operations {
		if op.Path == hooksPath {
			stripOp = op
			break
		}
	}
	if stripOp.Op != "strip" {
		t.Fatalf("missing strip op for %s: %+v", hooksPath, out.Operations)
	}
	s := stripOp.Content
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
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		t.Fatalf("parse final: %v", err)
	}
	if v, _ := parsed["version"].(float64); int(v) != 1 {
		t.Fatalf("user version = %v, want 1", parsed["version"])
	}
}
