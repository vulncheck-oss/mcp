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

func TestMakeSearchIndexHandler(t *testing.T) {
	tests := []struct {
		name       string
		args       searchIndexArgs
		clientResp *client.IndexQueryResult
		clientErr  error
		wantLimit  int
		wantErr    bool
		wantResult searchIndexResult
	}{
		{
			name:      "returns formatted result",
			args:      searchIndexArgs{Index: "vulncheck-nvd2", Limit: 5},
			wantLimit: 5,
			clientResp: &client.IndexQueryResult{
				Data:       []json.RawMessage{json.RawMessage(`{"id":"CVE-2021-44228"}`)},
				NextCursor: "next",
				Total:      100,
			},
			wantResult: searchIndexResult{
				Data:       []json.RawMessage{json.RawMessage(`{"id":"CVE-2021-44228"}`)},
				NextCursor: "next",
				Total:      100,
			},
		},
		{
			name:       "zero limit defaults to 1",
			args:       searchIndexArgs{Index: "vulncheck-nvd2", Limit: 0},
			wantLimit:  1,
			clientResp: &client.IndexQueryResult{Data: []json.RawMessage{}, Total: 0},
		},
		{
			name:       "passes cve and cursor through",
			args:       searchIndexArgs{Index: "vulncheck-kev", CVE: "CVE-2021-44228", Cursor: "page2", Limit: 3},
			wantLimit:  3,
			clientResp: &client.IndexQueryResult{Data: []json.RawMessage{}, Total: 0},
		},
		{
			name:      "client error propagates",
			args:      searchIndexArgs{Index: "bad-index", Limit: 1},
			wantLimit: 1,
			clientErr: errors.New("api error"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery client.SearchIndexQuery

			mock := &mockClient{
				searchIndexFn: func(_ context.Context, q client.SearchIndexQuery) (*client.IndexQueryResult, error) {
					gotQuery = q
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeSearchIndexHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.args.Index, gotQuery.Index)
			assert.Equal(t, tt.args.CVE, gotQuery.CVE)
			assert.Equal(t, tt.args.Cursor, gotQuery.Cursor)
			assert.Equal(t, tt.wantLimit, gotQuery.Limit)

			text := result.Content[0].(*mcp.TextContent).Text
			var got searchIndexResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantResult.Total, got.Total)
			assert.Equal(t, tt.wantResult.NextCursor, got.NextCursor)
			assert.Len(t, got.Data, len(tt.wantResult.Data))
		})
	}
}
