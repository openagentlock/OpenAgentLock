module github.com/openagentlock/openagentlock/control-plane

go 1.21

// Dependencies will be added as the API surface lands. Kept empty here so
// `go mod tidy` produces a deterministic graph from the imports below.

require (
	golang.org/x/crypto v0.31.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.29.0 // indirect
