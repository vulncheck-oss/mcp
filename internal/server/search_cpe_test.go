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
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func TestMakeSearchCPEHandler(t *testing.T) {
	cpe1 := "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
	cpe2 := "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*"

	tests := []struct {
		name       string
		args       searchCPEArgs
		clientResp *client.SearchCPEResult
		clientErr  error
		wantErr    bool
		wantQuery  client.SearchCPEQuery
		wantTotal  int
		wantLen    int
	}{
		{
			name: "returns matching CPEs and CVEs",
			args: searchCPEArgs{Vendor: "apache", Product: "log4j"},
			clientResp: &client.SearchCPEResult{
				Data: []vulncheck.SearchResponseDataOut{
					{Cpe: &cpe1, Cves: []string{"CVE-2021-44228"}},
					{Cpe: &cpe2, Cves: []string{"CVE-2021-45046"}},
				},
				Total: 2,
			},
			wantQuery: client.SearchCPEQuery{Vendor: "apache", Product: "log4j"},
			wantTotal: 2,
			wantLen:   2,
		},
		{
			name:       "passes vulnerable_only flag",
			args:       searchCPEArgs{Vendor: "apache", VulnerableOnly: true},
			clientResp: &client.SearchCPEResult{Data: []vulncheck.SearchResponseDataOut{{Cpe: &cpe1}}, Total: 1},
			wantQuery:  client.SearchCPEQuery{Vendor: "apache", VulnerableOnly: true},
			wantTotal:  1,
			wantLen:    1,
		},
		{
			name:       "empty result",
			args:       searchCPEArgs{Vendor: "unknown"},
			clientResp: &client.SearchCPEResult{Data: []vulncheck.SearchResponseDataOut{}, Total: 0},
			wantQuery:  client.SearchCPEQuery{Vendor: "unknown"},
		},
		{
			name:      "client error propagates",
			args:      searchCPEArgs{Product: "bad"},
			clientErr: errors.New("search failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery client.SearchCPEQuery

			mock := &mockClient{
				searchCPEFn: func(_ context.Context, q client.SearchCPEQuery) (*client.SearchCPEResult, error) {
					gotQuery = q
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeSearchCPEHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantQuery, gotQuery)

			text := result.Content[0].(*mcp.TextContent).Text
			var got client.SearchCPEResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantTotal, got.Total)
			assert.Len(t, got.Data, tt.wantLen)
		})
	}
}
