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

func geminiApplyBody(fx gateFixture, dir, binary string, existing map[string]string) string {
	if existing == nil {
		existing = map[string]string{}
	}
	ex, _ := json.Marshal(existing)
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["gemini"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": %q,
		"existing_files": %s
	}`, fx.sessionID, dir, binary, ex)
}

func postGeminiApply(t *testing.T, fx gateFixture, dir, binary string, existing map[string]string) *http.Response {
	t.Helper()
	res, err := http.Post(
		fx.srv.URL+"/v1/install/apply",
		"application/json",
		strings.NewReader(geminiApplyBody(fx, dir, binary, existing)),
	)
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

func findGeminiSettingsOp(t *testing.T, ops []fileOp) fileOp {
	t.Helper()
	for _, op := range ops {
		if strings.HasSuffix(op.Path, "settings.json") {
			return op
		}
	}
	t.Fatalf("no settings.json op in %+v", ops)
	return fileOp{}
}

func TestInstallPlan_GeminiProducesWriteOpNoWarnings(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["gemini"],
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
	if len(ops) != 1 {
		t.Fatalf("expected exactly one op (settings.json), got %d: %+v", len(ops), ops)
	}
	op, _ := ops[0].(map[string]any)
	path, _ := op["path"].(string)
	if !strings.HasSuffix(path, "settings.json") {
		t.Fatalf("expected settings.json path, got %q", path)
	}
	content, _ := op["content"].(string)
	for _, want := range []string{
		`"_agentlock"`,
		`"BeforeTool"`,
		`"AfterTool"`,
		`"SessionStart"`,
		`"SessionEnd"`,
		`"type": "command"`,
		`'/usr/local/bin/agentlock' hook gemini pre-tool-use`,
		`"AGENTLOCK_DAEMON_URL": "http://127.0.0.1:7878"`,
		`"timeout": 60000`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("missing %q in settings.json content: %s", want, content)
		}
	}
	// Gemini has no MCP-gap caveat; warnings must be empty.
	warns, _ := plan["warnings"].([]any)
	if len(warns) != 0 {
		t.Fatalf("expected no warnings for gemini, got: %+v", warns)
	}
}

func TestInstallApply_GeminiCreatesSettingsWhenMissing(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	res := postGeminiApply(t, fx, dir, "/usr/local/bin/agentlock", nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}
	op := findGeminiSettingsOp(t, out.Operations)
	if op.BackupPath != "" {
		t.Fatalf("no backup expected when file was missing; got %q", op.BackupPath)
	}
	for _, want := range []string{
		`"BeforeTool"`,
		`"AfterTool"`,
		`"SessionStart"`,
		`"SessionEnd"`,
		`hook gemini pre-tool-use`,
	} {
		if !strings.Contains(op.Content, want) {
			t.Fatalf("missing %q: %s", want, op.Content)
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

func TestInstallApply_GeminiPreservesExistingUserHooksAndOtherSettings(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))

	user := `{
		"theme": "Atom One",
		"selectedAuthType": "oauth-personal",
		"hooks": {
			"BeforeTool": [
				{"matcher": "write_file", "hooks": [{"type": "command", "command": "user-hook.sh"}]}
			]
		}
	}`
	res := postGeminiApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		settingsPath: user,
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	op := findGeminiSettingsOp(t, out.Operations)
	s := op.Content
	if !strings.Contains(s, "user-hook.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if !strings.Contains(s, "_agentlock") {
		t.Fatalf("our entry missing: %s", s)
	}
	if !strings.Contains(s, `"theme": "Atom One"`) {
		t.Fatalf("non-hooks settings clobbered: %s", s)
	}
	if !strings.Contains(s, `"selectedAuthType": "oauth-personal"`) {
		t.Fatalf("auth setting clobbered: %s", s)
	}
	if op.BackupPath == "" {
		t.Fatalf("expected backup_path on settings op when existing file supplied")
	}
}

func TestInstallApply_GeminiIdempotent(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))

	first := decodeApplyResponse(t, postGeminiApply(t, fx, dir, "/usr/local/bin/agentlock", nil))
	firstOp := findGeminiSettingsOp(t, first.Operations)

	second := decodeApplyResponse(t, postGeminiApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		settingsPath: firstOp.Content,
	}))
	secondOp := findGeminiSettingsOp(t, second.Operations)
	got := strings.Count(secondOp.Content, `"_agentlock"`)
	if got != 4 {
		t.Fatalf("expected 4 _agentlock entries, got %d: %s", got, secondOp.Content)
	}
}

func TestInstallUninstall_GeminiStripsOurEntriesOnly(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))

	user := `{"theme":"Default","hooks":{"BeforeTool":[{"matcher":"write_file","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	applyOut := decodeApplyResponse(t, postGeminiApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		settingsPath: user,
	}))
	mergedOp := findGeminiSettingsOp(t, applyOut.Operations)

	res := postUninstallWithExisting(t, fx, fx.sessionID, map[string]string{
		settingsPath: mergedOp.Content,
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeUninstallResponse(t, res)
	var stripOp uninstallOp
	for _, op := range out.Operations {
		if op.Path == settingsPath {
			stripOp = op
			break
		}
	}
	if stripOp.Op != "strip" {
		t.Fatalf("missing strip op for %s: %+v", settingsPath, out.Operations)
	}
	if stripOp.EntriesRemoved == 0 {
		t.Fatalf("entries_removed = 0; expected >0: %+v", stripOp)
	}
	s := stripOp.Content
	if !strings.Contains(s, "mine.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if !strings.Contains(s, `"theme":"Default"`) && !strings.Contains(s, `"theme": "Default"`) {
		t.Fatalf("theme setting lost in strip: %s", s)
	}
	if strings.Contains(s, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", s)
	}
	if strings.Contains(s, "agentlock hook gemini") {
		t.Fatalf("our shim invocation should be gone: %s", s)
	}
}
