package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// GET /v1/mode reports the effective daemon mode. Default is firewall
// when no env and no runtime override are set.
func TestModeGet_DefaultsToFirewall(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	// Clear any leftover runtime override from a sibling test running
	// in the same process.
	runtimeMode.Store("")
	fx := newGateFixture(t, enforcePolicyYAML)
	res, err := http.Get(fx.srv.URL + "/v1/mode")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["mode"] != "firewall" {
		t.Fatalf("default mode = %v, want firewall", out["mode"])
	}
}

// PATCH /v1/mode flips the runtime override and GET reflects it.
func TestModePatch_FlipsToMonitor(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("")
	fx := newGateFixture(t, enforcePolicyYAML)

	req, _ := http.NewRequest(
		http.MethodPatch,
		fx.srv.URL+"/v1/mode",
		strings.NewReader(`{"mode":"monitor"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}

	getRes, err := http.Get(fx.srv.URL + "/v1/mode")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getRes.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(getRes.Body).Decode(&out)
	if out["mode"] != "monitor" {
		t.Fatalf("after PATCH mode = %v, want monitor", out["mode"])
	}
	// Cleanup so sibling tests don't inherit the override.
	runtimeMode.Store("")
}

// PATCH /v1/mode {"mode":""} clears the runtime override, falling back
// to env / default.
func TestModePatch_EmptyClearsOverride(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("monitor")
	fx := newGateFixture(t, enforcePolicyYAML)

	req, _ := http.NewRequest(
		http.MethodPatch,
		fx.srv.URL+"/v1/mode",
		strings.NewReader(`{"mode":""}`),
	)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH: %v", err)
	}
	res.Body.Close()

	getRes, err := http.Get(fx.srv.URL + "/v1/mode")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getRes.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(getRes.Body).Decode(&out)
	if out["mode"] != "firewall" {
		t.Fatalf("cleared override should fall back to firewall, got %v", out["mode"])
	}
}

// Invalid PATCH body is rejected with 400.
func TestModePatch_RejectsUnknownMode(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	req, _ := http.NewRequest(
		http.MethodPatch,
		fx.srv.URL+"/v1/mode",
		strings.NewReader(`{"mode":"panic"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}
