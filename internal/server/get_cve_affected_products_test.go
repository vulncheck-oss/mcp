package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// jsonInt reads a count out of a decoded payload. JSON numbers decode to float64,
// but these are exact integer counts, so they are compared as ints.
func jsonInt(t *testing.T, payload map[string]any, key string) int {
	t.Helper()
	raw, ok := payload[key].(float64)
	require.True(t, ok, "expected %q to be a number", key)
	return int(raw)
}

func TestMakeGetCVEAffectedProductsHandler(t *testing.T) {
	tests := []struct {
		name       string
		args       getCVEAffectedProductsArgs
		clientResp *client.CVEAffectedResult
		clientErr  error
		wantErr    bool
		assertJSON func(t *testing.T, payload map[string]any)
	}{
		{
			name: "returns products and platforms",
			args: getCVEAffectedProductsArgs{CVE: "CVE-2026-22561"},
			clientResp: &client.CVEAffectedResult{
				CVE: "CVE-2026-22561",
				Products: []client.AffectedProduct{{
					Part: "a", Vendor: "anthropic", Product: "claude",
					Versions: []string{"<1.1.3363"}, Sources: []string{"nvd"},
				}},
				Platforms: []client.AffectedProduct{{
					Part: "o", Vendor: "microsoft", Product: "windows", Sources: []string{"nvd"},
				}},
				TotalProducts:  1,
				TotalPlatforms: 1,
			},
			assertJSON: func(t *testing.T, payload map[string]any) {
				t.Helper()
				products, ok := payload["affected_products"].([]any)
				require.True(t, ok)
				require.Len(t, products, 1)
				first, ok := products[0].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "anthropic", first["vendor"])
				assert.Equal(t, "claude", first["product"])
				assert.Equal(t, "a", first["part"])
				assert.Equal(t, []any{"nvd"}, first["sources"],
					"per-entry attribution must survive serialization")
				assert.Equal(t, 1, jsonInt(t, payload, "total_affected_products"))
				assert.Contains(t, payload, "platforms")
			},
		},
		{
			name: "note survives serialization when nothing is affected",
			args: getCVEAffectedProductsArgs{CVE: "CVE-2025-59532"},
			clientResp: &client.CVEAffectedResult{
				CVE:      "CVE-2025-59532",
				Products: []client.AffectedProduct{},
				Note:     "no CPE configurations are published for this CVE",
			},
			assertJSON: func(t *testing.T, payload map[string]any) {
				t.Helper()
				assert.Empty(t, payload["affected_products"])
				assert.Contains(t, payload["note"], "no CPE configurations")
			},
		},
		{
			name: "truncation flag is exposed to the caller",
			args: getCVEAffectedProductsArgs{CVE: "CVE-2018-3639"},
			clientResp: &client.CVEAffectedResult{
				CVE:           "CVE-2018-3639",
				Products:      []client.AffectedProduct{{Vendor: "v", Product: "p"}},
				TotalProducts: 282,
				Truncated:     true,
			},
			assertJSON: func(t *testing.T, payload map[string]any) {
				t.Helper()
				assert.Equal(t, true, payload["truncated"])
				assert.Equal(t, 282, jsonInt(t, payload, "total_affected_products"))
			},
		},
		{
			name:      "client error propagates",
			args:      getCVEAffectedProductsArgs{CVE: "CVE-2099-99999"},
			clientErr: errors.New("index unreachable"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotCVE string

			mock := &mockClient{
				getCVEAffectedFn: func(_ context.Context, cve string) (*client.CVEAffectedResult, error) {
					gotCVE = cve
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeGetCVEAffectedProductsHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.args.CVE, gotCVE)

			require.Len(t, result.Content, 1)
			text, ok := result.Content[0].(*mcp.TextContent)
			require.True(t, ok)

			var payload map[string]any
			require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
			assert.Equal(t, tt.args.CVE, payload["cve"])

			if tt.assertJSON != nil {
				tt.assertJSON(t, payload)
			}
		})
	}
}
