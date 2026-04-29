// Package dashboard serves the firewall-admin web UI on a separate port
// (default 127.0.0.1:7879) per docs/guide/dashboard.md.
//
// The UI is a TanStack Start SPA built from control-plane/dashboard-ui/.
// The build output lives in ./dist (committed or generated via `just
// dashboard-build`) and is embedded here via go:embed so the Go binary
// ships with the dashboard. Any unknown route renders index.html so the
// SPA's client-side router can handle deep links.

package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns the dashboard mux. Serves /assets/* with long-cache
// headers (Vite's hashed-filename bundles), index.html at /, and
// everything else also renders index.html for SPA deep-link support.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Strip the "dist/" prefix so "/" maps to dist/index.html.
	distRoot, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("dashboard: sub FS: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(distRoot))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			serveIndex(w, r, distRoot)
			return
		}
		// If the file exists in dist, serve it as-is (JS, CSS, fonts,
		// favicon, etc). Otherwise fall back to index.html so the client
		// router can resolve the route.
		f, err := distRoot.Open(p)
		if err != nil {
			serveIndex(w, r, distRoot)
			return
		}
		_ = f.Close()
		// Hashed asset files get a one-year cache; everything else stays
		// uncached so a rebuild is picked up on refresh.
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})

	return corsForLocalAPI(mux)
}

func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS) {
	b, err := fs.ReadFile(root, "index.html")
	if err != nil {
		// Dist not built yet — friendlier than a stack trace.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(dashboardNotBuiltHTML))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
	_ = r // keep signature tidy
}

// corsForLocalAPI rejects framing and locks script/connect-src to
// loopback + the control-plane API. The dashboard and API run on
// different ports (7879 vs 7878) so the API side whitelists loopback
// origins; this CSP is defense in depth against an external site
// embedding the dashboard.
func corsForLocalAPI(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self' "+
				"http://127.0.0.1:7878 ws://127.0.0.1:7878 "+
				"http://localhost:7878 ws://localhost:7878")
		h.ServeHTTP(w, r)
	})
}

const dashboardNotBuiltHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>OpenAgentLock dashboard — not built</title>
<style>body{font-family:-apple-system,sans-serif;max-width:640px;margin:80px auto;padding:0 20px;color:#e6e8eb;background:#0b0d10}
code{background:#1a1f27;padding:2px 6px;border-radius:3px}
h1{font-size:16px;letter-spacing:0.05em;text-transform:uppercase;color:#8b95a3}
a{color:#60a5fa}</style></head><body>
<h1>Dashboard bundle not built</h1>
<p>The control-plane is running but the web UI hasn't been compiled yet. Run:</p>
<pre><code>cd control-plane/dashboard-ui
bun install
bun run build</code></pre>
<p>Then restart the daemon (<code>just cp-serve</code>). The embedded bundle lives at <code>control-plane/internal/dashboard/dist/</code>.</p>
</body></html>`
