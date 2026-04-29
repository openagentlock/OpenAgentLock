package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Until the API is signed off, every non-health route must respond 501
// with a body that names the canonical method. This test pins that
// contract so we don't accidentally ship a half-implemented handler.

func TestHealth_OK(t *testing.T) {
	srv := httptest.NewServer(NewRouter())
	defer srv.Close()

	res, err := http.Get(srv.URL + "/v1/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("health: want 200, got %d", res.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health body: want status=ok, got %v", body)
	}
}

func TestEveryNonHealthRouteIs501UntilSignoff(t *testing.T) {
	srv := httptest.NewServer(NewRouter())
	defer srv.Close()

	type call struct {
		method string
		path   string
	}
	cases := []call{
		// POST /v1/sessions and POST /v1/gates/check are implemented; their
		// own test suites cover them. The bare router (no Deps) still hits
		// the 501 fallback so the contract check holds for them too via
		// the nil-Deps guard in each handler.
		{"POST", "/v1/sessions/abc/rotate"},
		{"POST", "/v1/sessions/abc/end"},
		{"POST", "/v1/approvals/abc/approve"},
		{"POST", "/v1/approvals/abc/refuse"},
		{"GET", "/v1/approvals/pending"},
		{"GET", "/v1/ledger/proof/42"},
		{"GET", "/v1/sessions/abc/report"},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusNotImplemented {
				t.Fatalf("%s %s: want 501, got %d", c.method, c.path, res.StatusCode)
			}
			var body map[string]string
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["error"] != "not_implemented" {
				t.Fatalf("body.error: want not_implemented, got %v", body)
			}
			if body["method"] == "" {
				t.Fatalf("body.method should be the canonical name")
			}
		})
	}
}
