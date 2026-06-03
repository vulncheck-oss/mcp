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

func TestMakeIdentifyComponentHandler(t *testing.T) {
	tests := []struct {
		name       string
		args       identifyComponentArgs
		clientResp []client.IdentifyResult
		clientErr  error
		wantErr    bool
		wantLen    int
		wantCPE    string
	}{
		{
			name: "returns identifiers for vendor and product",
			args: identifyComponentArgs{Vendor: "microsoft corporation", Product: "office 2016"},
			clientResp: []client.IdentifyResult{
				{
					Identifiers: client.IdentifyIdentifiers{
						CPE: []client.IdentifyIdentifier{
							{Value: "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*", Confidence: client.IdentifyConfidence{Level: "high", Source: "inference"}},
						},
					},
				},
			},
			wantLen: 1,
			wantCPE: "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*",
		},
		{
			name:       "empty result",
			args:       identifyComponentArgs{Vendor: "unknown", Product: "unknown"},
			clientResp: []client.IdentifyResult{},
			wantLen:    0,
		},
		{
			name:      "client error propagates",
			args:      identifyComponentArgs{Vendor: "microsoft corporation", Product: "office 2016"},
			clientErr: errors.New("identify failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotVendor, gotProduct, gotVersion string

			mock := &mockClient{
				identifyComponentFn: func(_ context.Context, vendor, product, version string) ([]client.IdentifyResult, error) {
					gotVendor, gotProduct, gotVersion = vendor, product, version
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeIdentifyComponentHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.args.Vendor, gotVendor)
			assert.Equal(t, tt.args.Product, gotProduct)
			assert.Equal(t, tt.args.Version, gotVersion)

			text := result.Content[0].(*mcp.TextContent).Text
			var got []client.IdentifyResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			require.Len(t, got, tt.wantLen)

			if tt.wantCPE != "" {
				require.NotEmpty(t, got[0].Identifiers.CPE)
				assert.Equal(t, tt.wantCPE, got[0].Identifiers.CPE[0].Value)
			}
		})
	}
}
