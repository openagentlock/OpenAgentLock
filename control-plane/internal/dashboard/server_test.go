package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboard_ServesIndexOnRoot(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	b, _ := io.ReadAll(res.Body)
	body := string(b)
	// Title is stable across placeholder + built SPA bundle; the SSE
	// URL used to be inline in the vanilla-JS HTML but now lives in
	// the hashed JS bundle emitted by Vite, so we don't assert on it.
	if !strings.Contains(body, "OpenAgentLock") {
		snippet := body
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		t.Fatalf("expected dashboard title in body; got first 200 bytes: %q", snippet)
	}
	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestDashboard_Healthz(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestDashboard_CspAndFrameHeaders(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing XFO header")
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("CSP = %q", csp)
	}
}

func TestDashboard_UnknownPathStillServesIndex(t *testing.T) {
	// SPA fallback: any unknown path returns the shell so future client-
	// side routing works without server changes.
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/any/thing/here")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
}
