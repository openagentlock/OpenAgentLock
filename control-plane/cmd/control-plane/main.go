// OpenAgentLock control-plane: HTTP server that owns policy evaluation,
// approval queue, and ledger appends. Designed to run inside Docker on
// the developer's machine and talk to the CLI over loopback (or unix
// socket where supported).
//
// This is a scaffold. The HTTP routes mirror api/openapi.yaml; handlers
// return 501 Not Implemented until the API surface is signed off.

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/api"
	"github.com/openagentlock/openagentlock/control-plane/internal/auth"
	"github.com/openagentlock/openagentlock/control-plane/internal/dashboard"
	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

func main() {
	addr := os.Getenv("AGENTLOCK_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:7878"
	}
	if len(os.Args) > 1 && os.Args[1] == "--health" {
		runHealthProbe(addr)
		return
	}
	home := os.Getenv("AGENTLOCK_HOME")
	if home == "" {
		log.Fatalf("AGENTLOCK_HOME is required (ledger state lives there)")
	}

	store, err := storage.NewMemory(home)
	if err != nil {
		log.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	pol, err := loadPolicy(os.Getenv("AGENTLOCK_POLICY"))
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	log.Printf("policy loaded: %s (mode=%s, gates=%d)", pol.Hash, pol.Mode, len(pol.Gates))

	authCfg, err := auth.LoadConfig()
	if err != nil {
		log.Fatalf("auth config: %v", err)
	}
	// Force the auth directory under the same AGENTLOCK_HOME the rest of
	// the daemon uses (LoadConfig walks the env separately for isolation,
	// but once we're booting we want every persistent file colocated).
	authCfg.HomeDir = home
	authCfg.UsersDir = filepath.Join(home, "auth")
	authN, err := auth.Build(authCfg)
	if err != nil {
		log.Fatalf("auth build: %v", err)
	}
	if authN.Mode() != auth.ModeNone {
		users := authN.UsersCount()
		log.Printf("auth mode=%s users=%d", authN.Mode(), users)
		if users == 0 && authN.Mode() == auth.ModePassword {
			log.Printf("auth: no users configured — POST /v1/auth/bootstrap {username,password} to create the first one")
		}
	}

	srv := &http.Server{
		Addr: addr,
		Handler: api.NewRouter(api.Deps{
			Store:         store,
			Policy:        pol,
			PinStorePath:  filepath.Join(home, "pinned-mcp.json"),
			AgentlockHome: home,
			PolicyPath:    os.Getenv("AGENTLOCK_POLICY"),
			Auth:          authN,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("openagentlock control-plane listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	dashAddr := os.Getenv("AGENTLOCK_DASHBOARD_LISTEN")
	if dashAddr == "" {
		dashAddr = "127.0.0.1:7879"
	}
	dashSrv := &http.Server{
		Addr:              dashAddr,
		Handler:           dashboard.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("openagentlock dashboard listening on %s", dashAddr)
		if err := dashSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("dashboard server stopped: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = dashSrv.Shutdown(ctx)
	log.Printf("control-plane stopped")
}

// runHealthProbe is invoked when the binary is run as `agentlockd --health`
// (e.g. from the docker HEALTHCHECK). Distroless has no curl/wget, so we
// reuse the binary itself as the probe. The listen addr may be 0.0.0.0:port;
// rewrite to 127.0.0.1 for the probe.
func runHealthProbe(listen string) {
	probeAddr := listen
	if h, p, ok := splitHostPort(listen); ok && (h == "" || h == "0.0.0.0" || h == "::") {
		probeAddr = "127.0.0.1:" + p
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get("http://" + probeAddr + "/v1/health")
	if err != nil {
		log.Printf("healthcheck: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("healthcheck: status %d", resp.StatusCode)
		os.Exit(1)
	}
}

func splitHostPort(addr string) (host, port string, ok bool) {
	i := -1
	for j := len(addr) - 1; j >= 0; j-- {
		if addr[j] == ':' {
			i = j
			break
		}
	}
	if i < 0 {
		return "", "", false
	}
	return addr[:i], addr[i+1:], true
}

// loadPolicy reads $AGENTLOCK_POLICY if set; otherwise returns a built-in
// safe default (monitor mode, destructive-bash only) so the daemon always
// starts with *some* policy bound to session attestations.
func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return policy.LoadBytes([]byte(defaultPolicyYAML))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return policy.Load(f)
}

const defaultPolicyYAML = `
version: 1
mode: monitor
defaults:
  bash: allow
gates:
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+(-[rRfF]+\s+)+\S+'
        - 'git\s+push\s+.*--force'
        - 'kubectl\s+delete\s+'
        - 'DROP\s+(TABLE|DATABASE|SCHEMA)'
        - 'chmod\s+-R\b'
    evaluate:
      - kind: always
        action: deny
`
