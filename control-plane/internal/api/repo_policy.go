package api

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

const repoPolicyFileName = ".agentlock.yaml"

func resolvePolicyForCwd(d Deps, sessionPolicyHash, cwd string) *policy.Policy {
	base := resolvePolicy(d, sessionPolicyHash)
	if base == nil || cwd == "" {
		return base
	}
	path, data, err := findRepoPolicy(cwd)
	if err != nil || path == "" {
		return base
	}
	merged, err := policy.MergeRestrictiveExtension(base, data, "per-repo:"+path)
	if err != nil {
		return base
	}
	return merged
}

func findRepoPolicy(cwd string) (string, []byte, error) {
	dir, err := normalizeRepoPolicyCwd(cwd)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", nil, err
	}
	if !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		candidate := filepath.Join(dir, repoPolicyFileName)
		data, err := os.ReadFile(candidate)
		if err == nil {
			return candidate, data, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", nil, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil, nil
		}
		dir = parent
	}
}

func normalizeRepoPolicyCwd(cwd string) (string, error) {
	if cwd == "" || strings.ContainsRune(cwd, 0) || !utf8.ValidString(cwd) {
		return "", errors.New("invalid cwd")
	}
	if !filepath.IsAbs(cwd) {
		return "", errors.New("cwd must be absolute")
	}
	for _, part := range strings.Split(filepath.ToSlash(cwd), "/") {
		if part == ".." {
			return "", errors.New("cwd must not contain parent traversal")
		}
	}
	return filepath.Clean(cwd), nil
}
