package api

// ledgerMatcherInput keeps only fields that can drive dashboard rule
// creation. It intentionally avoids storing full tool inputs or tool
// responses in the SSE ledger stream.
func ledgerMatcherInput(input map[string]any) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, key := range []string{"command", "file_path", "path", "url"} {
		if v, ok := input[key].(string); ok && v != "" {
			out[key] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
