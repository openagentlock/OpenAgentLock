package main

import (
	"context"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

func TestSeedGuardrailProviderKeysFromEnv(t *testing.T) {
	store, err := storage.NewMemory(t.TempDir())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	env := map[string]string{
		"NVIDIA_API_KEY":     " nvapi-test ",
		"OPENROUTER_API_KEY": "sk-or-test",
	}
	seeded, err := seedGuardrailProviderKeys(context.Background(), store, func(k string) string {
		return env[k]
	})
	if err != nil {
		t.Fatalf("seedGuardrailProviderKeys: %v", err)
	}
	if len(seeded) != 2 || seeded[0] != "nvidia" || seeded[1] != "openrouter" {
		t.Fatalf("seeded = %+v", seeded)
	}

	nvidia, ok, err := store.GetGuardrailProviderConfig(context.Background(), "nvidia")
	if err != nil || !ok || nvidia.APIKey.Value() != "nvapi-test" {
		t.Fatalf("nvidia cfg = %+v ok=%v err=%v", nvidia, ok, err)
	}
	openrouter, ok, err := store.GetGuardrailProviderConfig(context.Background(), "openrouter")
	if err != nil || !ok || openrouter.APIKey.Value() != "sk-or-test" {
		t.Fatalf("openrouter cfg = %+v ok=%v err=%v", openrouter, ok, err)
	}
}

func TestSeedGuardrailProviderKeysSkipsEmptyEnv(t *testing.T) {
	store, err := storage.NewMemory(t.TempDir())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	seeded, err := seedGuardrailProviderKeys(context.Background(), store, func(string) string {
		return "   "
	})
	if err != nil {
		t.Fatalf("seedGuardrailProviderKeys: %v", err)
	}
	if len(seeded) != 0 {
		t.Fatalf("seeded = %+v", seeded)
	}
}
