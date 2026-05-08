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

func codexApplyBody(fx gateFixture, dir, binary string, existing map[string]string) string {
	if existing == nil {
		existing = map[string]string{}
	}
	ex, _ := json.Marshal(existing)
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["codex"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": %q,
		"existing_files": %s
	}`, fx.sessionID, dir, binary, ex)
}

func postCodexApply(t *testing.T, fx gateFixture, dir, binary string, existing map[string]string) *http.Response {
	t.Helper()
	res, err := http.Post(
		fx.srv.URL+"/v1/install/apply",
		"application/json",
		strings.NewReader(codexApplyBody(fx, dir, binary, existing)),
	)
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

// findCodexHooksOp returns the hooks.json op (not config.toml).
func findCodexHooksOp(t *testing.T, ops []fileOp) fileOp {
	t.Helper()
	for _, op := range ops {
		if strings.HasSuffix(op.Path, "hooks.json") {
			return op
		}
	}
	t.Fatalf("no hooks.json op in %+v", ops)
	return fileOp{}
}

func findCodexTomlOp(ops []fileOp) (fileOp, bool) {
	for _, op := range ops {
		if strings.HasSuffix(op.Path, "config.toml") {
			return op, true
		}
	}
	return fileOp{}, false
}

func TestInstallPlan_CodexProducesWriteOpAndWarning(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["codex"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": "/usr/local/bin/agentlock",
		"existing_files": {%q: "codex_hooks = true\n"}
	}`, fx.sessionID, dir, tomlPath)
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
	if !strings.Contains(content, "'/usr/local/bin/agentlock' hook codex pre-tool-use") {
		t.Fatalf("expected shell-quoted shim command in content, got: %s", content)
	}
	if !strings.Contains(content, `"AGENTLOCK_DAEMON_URL": "http://127.0.0.1:7878"`) {
		t.Fatalf("expected daemon URL env, got: %s", content)
	}
	warns, _ := plan["warnings"].([]any)
	if len(warns) == 0 {
		t.Fatalf("expected MCP-gap warning, got: %+v", plan)
	}
	if !strings.Contains(warns[0].(string), "MCP tool calls are NOT gated") {
		t.Fatalf("warning text drift: %v", warns[0])
	}
}

func TestInstallApply_CodexAutoEnablesFlagWhenMissing(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	// config.toml exists but the flag isn't set: add [features].hooks.
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath: "# nothing relevant\n",
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	tomlOp, ok := findCodexTomlOp(out.Operations)
	if !ok {
		t.Fatalf("expected config.toml op in: %+v", out.Operations)
	}
	if !strings.Contains(tomlOp.Content, "[features]\nhooks = true") {
		t.Fatalf("expected [features].hooks = true appended, got:\n%s", tomlOp.Content)
	}
	if tomlOp.BackupPath == "" {
		t.Fatalf("expected backup_path on toml op (existing file present), got empty")
	}
}

// Regression: when config.toml contains [section] headers and no hooks
// flag, the new key must land in its own [features] table, not inside the
// last unrelated section.
func TestInstallApply_CodexFlagInsertedBeforeFirstSection(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	original := "[projects.\"/foo\"]\ntrust_level = \"trusted\"\n\n[tui.model_availability_nux]\n\"gpt-5.5\" = 4\n"
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath: original,
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	tomlOp, ok := findCodexTomlOp(out.Operations)
	if !ok {
		t.Fatalf("expected config.toml op in: %+v", out.Operations)
	}
	if !strings.Contains(tomlOp.Content, "\n[features]\nhooks = true\n") {
		t.Fatalf("missing standalone [features].hooks line:\n%s", tomlOp.Content)
	}
	// Original content must be preserved.
	if !strings.Contains(tomlOp.Content, "[tui.model_availability_nux]") {
		t.Fatalf("original sections must be preserved:\n%s", tomlOp.Content)
	}
	if !strings.Contains(tomlOp.Content, `"gpt-5.5" = 4`) {
		t.Fatalf("original section content must be preserved:\n%s", tomlOp.Content)
	}
}

func TestInstallApply_CodexMigratesLegacyFalseToFeaturesHooks(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath: "codex_hooks = false\n",
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	tomlOp, ok := findCodexTomlOp(out.Operations)
	if !ok {
		t.Fatalf("expected config.toml op: %+v", out.Operations)
	}
	if !strings.Contains(tomlOp.Content, "[features]\nhooks = true") {
		t.Fatalf("expected [features].hooks = true, got:\n%s", tomlOp.Content)
	}
	if strings.Contains(tomlOp.Content, "codex_hooks") {
		t.Fatalf("expected legacy codex_hooks line removed, got:\n%s", tomlOp.Content)
	}
	if tomlOp.BackupPath == "" {
		t.Fatalf("expected backup_path set; got empty")
	}
}

func TestInstallApply_CodexCreatesConfigWhenMissing(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	tomlOp, ok := findCodexTomlOp(out.Operations)
	if !ok {
		t.Fatalf("expected config.toml op when file missing: %+v", out.Operations)
	}
	if tomlOp.Content != "[features]\nhooks = true\n" {
		t.Fatalf("expected fresh [features].hooks=true content, got:\n%s", tomlOp.Content)
	}
	if tomlOp.BackupPath != "" {
		t.Fatalf("no backup expected when file was missing; got %q", tomlOp.BackupPath)
	}
}

func TestInstallApply_CodexFlagAlreadyTrue_NoTomlOp(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath: "[features]\nhooks = true\n",
	})
	defer res.Body.Close()
	out := decodeApplyResponse(t, res)
	if _, ok := findCodexTomlOp(out.Operations); ok {
		t.Fatalf("expected no config.toml op when [features].hooks is already true; got: %+v", out.Operations)
	}
}

func TestInstallApply_CodexWritesHooksJson(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))

	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath: "codex_hooks = true\n",
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}
	if len(out.Warnings) == 0 || !strings.Contains(out.Warnings[0], "MCP") {
		t.Fatalf("missing MCP warning: %+v", out.Warnings)
	}

	op := findCodexHooksOp(t, out.Operations)
	s := op.Content
	for _, want := range []string{
		`"_agentlock"`,
		`"PreToolUse"`,
		`"SessionStart"`,
		`"PostToolUse"`,
		`"Stop"`,
		`"type": "command"`,
		`'/usr/local/bin/agentlock' hook codex pre-tool-use`,
		`"AGENTLOCK_DAEMON_URL"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in hooks.json content: %s", want, s)
		}
	}

	// Ledger must show install.apply.
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

func TestInstallApply_CodexPreservesExistingUserHooks(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	user := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [{"type": "command", "command": "user-hook.sh"}]}
			]
		}
	}`
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath:  "codex_hooks = true\n",
		hooksPath: user,
	})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	op := findCodexHooksOp(t, out.Operations)
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

func TestInstallApply_CodexIdempotent(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	first := decodeApplyResponse(t, postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath: "codex_hooks = true\n",
	}))
	firstOp := findCodexHooksOp(t, first.Operations)

	second := decodeApplyResponse(t, postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath:  "codex_hooks = true\n",
		hooksPath: firstOp.Content,
	}))
	secondOp := findCodexHooksOp(t, second.Operations)
	got := strings.Count(secondOp.Content, `"_agentlock"`)
	if got != 4 {
		t.Fatalf("expected 4 _agentlock entries, got %d: %s", got, secondOp.Content)
	}
}

func TestInstallUninstall_CodexStripsOurEntriesOnly(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	tomlPath, _ := filepath.Abs(filepath.Join(dir, "config.toml"))
	hooksPath, _ := filepath.Abs(filepath.Join(dir, "hooks.json"))

	user := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	applyOut := decodeApplyResponse(t, postCodexApply(t, fx, dir, "/usr/local/bin/agentlock", map[string]string{
		tomlPath:  "codex_hooks = true\n",
		hooksPath: user,
	}))
	mergedOp := findCodexHooksOp(t, applyOut.Operations)

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
	if stripOp.EntriesRemoved == 0 {
		t.Fatalf("entries_removed = 0; expected >0: %+v", stripOp)
	}
	s := stripOp.Content
	if !strings.Contains(s, "mine.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if strings.Contains(s, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", s)
	}
	if strings.Contains(s, "agentlock hook codex") {
		t.Fatalf("our shim invocation should be gone: %s", s)
	}
}
