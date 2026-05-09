package guardrails

import "fmt"

type ProviderKind string

const (
	ProviderKindHostedAPI ProviderKind = "hosted_api"
)

type CatalogEntryKind string

const (
	CatalogEntryClassifierModel CatalogEntryKind = "classifier_model"
	CatalogEntryAccountPolicy   CatalogEntryKind = "account_policy"
)

type ProviderConfig struct {
	ProviderID string            `json:"provider_id"`
	APIKey     SecretString      `json:"api_key,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type EnabledEntry struct {
	ProviderID string `json:"provider_id"`
	EntryID    string `json:"entry_id"`
}

type SecretString string

func (s SecretString) Value() string {
	return string(s)
}

func (s SecretString) String() string {
	return "[redacted]"
}

func (s SecretString) GoString() string {
	return fmt.Sprintf("%q", s.String())
}
