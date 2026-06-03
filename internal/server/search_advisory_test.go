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
	v2 "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func TestMakeSearchAdvisoryHandler(t *testing.T) {
	tests := []struct {
		name       string
		args       searchAdvisoryArgs
		clientResp *client.SearchAdvisoryResult
		clientErr  error
		wantErr    bool
		wantLimit  int32
		wantTotal  int32
		wantLen    int
	}{
		{
			name: "returns advisory results",
			args: searchAdvisoryArgs{Name: "vulncheck", CveID: "CVE-2024-1234", Limit: 5},
			clientResp: &client.SearchAdvisoryResult{
				Data:  []v2.AdvisoryMitreCVEListV5Ref{{}},
				Total: 1,
			},
			wantLimit: 5,
			wantTotal: 1,
			wantLen:   1,
		},
		{
			name:       "zero limit defaults to 1",
			args:       searchAdvisoryArgs{Name: "vulncheck"},
			clientResp: &client.SearchAdvisoryResult{Data: []v2.AdvisoryMitreCVEListV5Ref{}, Total: 0},
			wantLimit:  1,
		},
		{
			name:      "client error propagates",
			args:      searchAdvisoryArgs{Name: "vulncheck"},
			clientErr: errors.New("api error"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery client.SearchAdvisoryQuery

			mock := &mockClient{
				searchAdvisoryFn: func(_ context.Context, q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
					gotQuery = q
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeSearchAdvisoryHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.args.Name, gotQuery.Name)
			assert.Equal(t, tt.args.CveID, gotQuery.CveID)
			assert.Equal(t, tt.wantLimit, gotQuery.Limit)

			text := result.Content[0].(*mcp.TextContent).Text
			var got client.SearchAdvisoryResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantTotal, got.Total)
			assert.Len(t, got.Data, tt.wantLen)
		})
	}
}
