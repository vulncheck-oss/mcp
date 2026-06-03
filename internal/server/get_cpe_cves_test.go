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

func TestMakeGetCPECVEsHandler(t *testing.T) {
	const cpeStr = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

	tests := []struct {
		name         string
		args         getCPECVEsArgs
		clientResp   *client.CPECVEsResult
		clientErr    error
		wantVulnOnly bool
		wantErr      bool
		wantCVEs     []string
		wantTotal    int
	}{
		{
			name:       "returns cpe, cves, and total",
			args:       getCPECVEsArgs{CPE: cpeStr},
			clientResp: &client.CPECVEsResult{CVEs: []string{"CVE-2021-44228", "CVE-2021-45046"}, Total: 2},
			wantCVEs:   []string{"CVE-2021-44228", "CVE-2021-45046"},
			wantTotal:  2,
		},
		{
			name:         "passes vulnerable_only flag",
			args:         getCPECVEsArgs{CPE: cpeStr, VulnerableOnly: true},
			wantVulnOnly: true,
			clientResp:   &client.CPECVEsResult{CVEs: []string{"CVE-2021-44228"}, Total: 1},
			wantCVEs:     []string{"CVE-2021-44228"},
			wantTotal:    1,
		},
		{
			name:       "nil cves returns empty array",
			args:       getCPECVEsArgs{CPE: cpeStr},
			clientResp: &client.CPECVEsResult{CVEs: nil, Total: 0},
		},
		{
			name:      "client error propagates",
			args:      getCPECVEsArgs{CPE: "bad-cpe"},
			clientErr: errors.New("search failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotCPE string
			var gotVulnOnly bool

			mock := &mockClient{
				getCPECVEsFn: func(_ context.Context, cpe string, vulnerableOnly bool) (*client.CPECVEsResult, error) {
					gotCPE, gotVulnOnly = cpe, vulnerableOnly
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeGetCPECVEsHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.args.CPE, gotCPE)
			assert.Equal(t, tt.wantVulnOnly, gotVulnOnly)

			text := result.Content[0].(*mcp.TextContent).Text
			var got getCPECVEsResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.args.CPE, got.CPE)
			assert.Equal(t, tt.wantTotal, got.Total)
			assert.Equal(t, tt.wantCVEs, got.CVEs)
		})
	}
}
