package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInstallCapabilities_ReflectsEnv(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	t.Setenv("AGENTLOCK_ALLOW_APPLY_REAL_HOME", "1")
	t.Setenv("AGENTLOCK_ALLOW_UNATTESTED", "")
	t.Setenv("AGENTLOCK_IN_CONTAINER", "1")

	srv := httptest.NewServer(NewRouter())
	defer srv.Close()

	res, err := http.Get(srv.URL + "/v1/install/capabilities")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", res.StatusCode)
	}

	var got InstallCapabilities
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := InstallCapabilities{
		ApplyEnabled:      true,
		RealHomeAllowed:   true,
		UnattestedAllowed: false,
		Container:         true,
	}
	if got != want {
		t.Fatalf("capabilities: want %+v, got %+v", want, got)
	}
}

func TestValidateHarnessConfigDirs(t *testing.T) {
	cases := []struct {
		name          string
		input         map[string]string
		agentlockHome string
		wantOK        bool
		wantKey       string
	}{
		{name: "nil ok", input: nil, wantOK: true},
		{name: "empty ok", input: map[string]string{}, wantOK: true},
		{name: "empty value ignored", input: map[string]string{"claude-code": ""}, wantOK: true},
		{name: "absolute canonical ok",
			input: map[string]string{"claude-code": "/Users/me/.claude", "codex": "/Users/me/.codex"},
			wantOK: true},
		{name: "relative rejected",
			input:   map[string]string{"claude-code": "relative/path"},
			wantOK:  false,
			wantKey: "claude-code"},
		{name: "double-dot segment rejected (non-canonical)",
			input:   map[string]string{"codex": "/Users/me/../foo"},
			wantOK:  false,
			wantKey: "codex"},
		{name: "trailing slash rejected (non-canonical)",
			input:   map[string]string{"claude-code": "/Users/me/.claude/"},
			wantOK:  false,
			wantKey: "claude-code"},
		{name: "under AGENTLOCK_HOME rejected",
			input:         map[string]string{"claude-code": "/var/lib/agentlock/secrets"},
			agentlockHome: "/var/lib/agentlock",
			wantOK:        false,
			wantKey:       "claude-code"},
		{name: "exact AGENTLOCK_HOME rejected",
			input:         map[string]string{"claude-code": "/var/lib/agentlock"},
			agentlockHome: "/var/lib/agentlock",
			wantOK:        false,
			wantKey:       "claude-code"},
		{name: "sibling of AGENTLOCK_HOME ok",
			input:         map[string]string{"claude-code": "/var/lib/agentlock-other"},
			agentlockHome: "/var/lib/agentlock",
			wantOK:        true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotKey, gotErr := validateHarnessConfigDirs(c.input, c.agentlockHome)
			if c.wantOK {
				if gotErr != nil {
					t.Fatalf("want ok, got err=%v key=%s", gotErr, gotKey)
				}
				return
			}
			if gotErr == nil {
				t.Fatalf("want error for %v, got nil", c.input)
			}
			if gotKey != c.wantKey {
				t.Fatalf("want key=%s, got key=%s (err=%v)", c.wantKey, gotKey, gotErr)
			}
		})
	}
}

func TestInstallCapabilities_DefaultsAreSecure(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "")
	t.Setenv("AGENTLOCK_ALLOW_APPLY_REAL_HOME", "")
	t.Setenv("AGENTLOCK_ALLOW_UNATTESTED", "")
	t.Setenv("AGENTLOCK_IN_CONTAINER", "")

	srv := httptest.NewServer(NewRouter())
	defer srv.Close()

	res, err := http.Get(srv.URL + "/v1/install/capabilities")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()

	var got InstallCapabilities
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Container may be true if the test runner is itself in a container, so
	// don't pin it. The three env-controlled fields must all be false.
	if got.ApplyEnabled || got.RealHomeAllowed || got.UnattestedAllowed {
		t.Fatalf("expected all gates off; got %+v", got)
	}
}
