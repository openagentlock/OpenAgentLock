package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

// sessionIDPattern enforces a strict character set so manifestPath
// cannot be tricked into writing outside install-manifests/. Matches
// ULID / UUID / simple slugs. Rejects any path separator, dot-dot,
// NUL, whitespace, or unicode.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ErrInvalidSessionID is returned when a session id contains characters
// that could escape the manifest directory.
var ErrInvalidSessionID = errors.New("invalid session id for manifest path")

// installManifest records every file OpenAgentLock touched for a session's
// install. Uninstall reads this to know which settings.json files to strip.
type installManifest struct {
	SessionID string             `json:"session_id"`
	AppliedAt time.Time          `json:"applied_at"`
	Entries   []installManifestE `json:"entries"`
}

type installManifestE struct {
	Harness      string `json:"harness"`
	SettingsPath string `json:"settings_path"`
	BackupPath   string `json:"backup_path"`
	DaemonURL    string `json:"daemon_url"`
}

// ErrManifestNotFound is returned when the manifest for the given session
// does not exist.
var ErrManifestNotFound = errors.New("install manifest not found")

func manifestDir(home string) string {
	return filepath.Join(home, "install-manifests")
}

// manifestPath builds the on-disk path for a manifest file. Returns an
// error when sessionID contains anything that could traverse out of the
// install-manifests directory.
func manifestPath(home, sessionID string) (string, error) {
	if !sessionIDPattern.MatchString(sessionID) {
		return "", fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	return filepath.Join(manifestDir(home), sessionID+".json"), nil
}

func readManifest(home, sessionID string) (installManifest, error) {
	path, err := manifestPath(home, sessionID)
	if err != nil {
		return installManifest{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return installManifest{}, ErrManifestNotFound
		}
		return installManifest{}, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m installManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return installManifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return m, nil
}

func writeManifest(home string, m installManifest) error {
	path, err := manifestPath(home, m.SessionID)
	if err != nil {
		return err
	}
	dir := manifestDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	return policy.AtomicWriteFile(path, b, 0o600)
}

// deleteManifest best-effort removes an active manifest. Used to roll
// back when ledger append fails after writeManifest succeeded.
func deleteManifest(home, sessionID string) error {
	path, err := manifestPath(home, sessionID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// archiveManifest renames the active manifest to an .uninstalled-<nano>
// suffix so the history survives but readManifest treats the session as
// no-longer-installed.
func archiveManifest(home, sessionID string) error {
	src, err := manifestPath(home, sessionID)
	if err != nil {
		return err
	}
	dst := fmt.Sprintf("%s.uninstalled-%d", src, time.Now().UnixNano())
	return os.Rename(src, dst)
}
