package api

import (
	"encoding/json"
	"testing"
)

func TestSummarizeToolResponse(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantSize    int
		wantSuccess bool
	}{
		{name: "nil", raw: `null`, wantSize: 0, wantSuccess: true},
		{name: "empty string", raw: `""`, wantSize: 0, wantSuccess: true},
		{name: "non-empty string", raw: `"total 0"`, wantSize: 7, wantSuccess: true},
		{
			name:        "anthropic tool_result is_error true",
			raw:         `{"content": "ENOENT", "is_error": true}`,
			wantSize:    -1,
			wantSuccess: false,
		},
		{
			name:        "anthropic tool_result is_error false",
			raw:         `{"content": "ok", "is_error": false}`,
			wantSize:    -1,
			wantSuccess: true,
		},
		{
			name:        "gemini error string non-empty",
			raw:         `{"error": "boom"}`,
			wantSize:    -1,
			wantSuccess: false,
		},
		{
			name:        "gemini error string empty",
			raw:         `{"error": ""}`,
			wantSize:    -1,
			wantSuccess: true,
		},
		{
			name:        "gemini error nested object",
			raw:         `{"error": {"code": 500}}`,
			wantSize:    -1,
			wantSuccess: false,
		},
		{
			name:        "gemini error null is treated as no error",
			raw:         `{"error": null}`,
			wantSize:    -1,
			wantSuccess: true,
		},
		{
			name:        "ordinary object with no failure marker",
			raw:         `{"stdout": "hi", "exit_code": 0}`,
			wantSize:    -1,
			wantSuccess: true,
		},
		{
			name:        "array payload",
			raw:         `[1, 2, 3]`,
			wantSize:    -1,
			wantSuccess: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp any
			if err := json.Unmarshal([]byte(tc.raw), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			gotSize, gotSuccess := summarizeToolResponse(resp)
			if gotSuccess != tc.wantSuccess {
				t.Fatalf("success: got %v, want %v", gotSuccess, tc.wantSuccess)
			}
			// wantSize == -1 means "size depends on JSON marshalling and
			// isn't worth pinning; just confirm it's non-zero".
			switch tc.wantSize {
			case -1:
				if gotSize <= 0 {
					t.Fatalf("size: got %d, want > 0", gotSize)
				}
			default:
				if gotSize != tc.wantSize {
					t.Fatalf("size: got %d, want %d", gotSize, tc.wantSize)
				}
			}
		})
	}
}
