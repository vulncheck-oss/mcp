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

func TestMakeSearchCVEHandler(t *testing.T) {
	id1 := "doc1"
	index1 := "vulncheck-nvd2"

	tests := []struct {
		name       string
		args       searchCVEArgs
		clientResp *client.SearchCVEResult
		clientErr  error
		wantErr    bool
		wantQuery  client.SearchCVEQuery
		wantTotal  int32
		wantLen    int
	}{
		{
			name: "returns hits across indices",
			args: searchCVEArgs{CVE: "CVE-2021-44228", Limit: 10},
			clientResp: &client.SearchCVEResult{
				Data:       []vulncheck.IndexCveSearchHit{{Id: &id1, Index: &index1}},
				Total:      1,
				NextCursor: "tok123",
			},
			wantQuery: client.SearchCVEQuery{CVE: "CVE-2021-44228", Limit: 10},
			wantTotal: 1,
			wantLen:   1,
		},
		{
			name:       "zero limit defaults to 1",
			args:       searchCVEArgs{CVE: "CVE-2099-99999"},
			clientResp: &client.SearchCVEResult{Data: []vulncheck.IndexCveSearchHit{}, Total: 0},
			wantQuery:  client.SearchCVEQuery{CVE: "CVE-2099-99999", Limit: 1},
		},
		{
			name:      "client error propagates",
			args:      searchCVEArgs{CVE: "CVE-2021-44228"},
			clientErr: errors.New("search failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery client.SearchCVEQuery

			mock := &mockClient{
				searchCVEFn: func(_ context.Context, q client.SearchCVEQuery) (*client.SearchCVEResult, error) {
					gotQuery = q
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeSearchCVEHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantQuery, gotQuery)

			text := result.Content[0].(*mcp.TextContent).Text
			var got client.SearchCVEResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantTotal, got.Total)
			assert.Len(t, got.Data, tt.wantLen)
		})
	}
}
