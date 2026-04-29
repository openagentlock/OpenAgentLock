package api

import (
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

func storageAppendFixture() storage.AppendInput {
	return storage.AppendInput{
		TS:          time.Unix(1_700_000_000, 0).UTC(),
		Source:      "system",
		ToolUseID:   "test.seed",
		Signer:      "software",
		PayloadHash: []byte("seed"),
		Sig:         []byte("sig"),
	}
}

// Thin alias + constructor so ledger_test.go can create a Memory store
// without importing the storage package inline everywhere.
type memoryStoreShim = storage.Memory

func newMemoryForTest(home string) (*memoryStoreShim, error) {
	return storage.NewMemory(home)
}
