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

// TestMakeSearchIndexHandler_ThreatIntelFilters covers the filters shared by the
// vulnerability, exploit and threat-intelligence indices, which were previously
// unreachable through this tool. Each one was confirmed against the API before
// being exposed.
func TestMakeSearchIndexHandler_ThreatIntelFilters(t *testing.T) {
	var got client.SearchIndexQuery
	vc := &mockClient{
		searchIndexFn: func(_ context.Context, q client.SearchIndexQuery) (*client.IndexQueryResult, error) {
			got = q
			return &client.IndexQueryResult{Data: []json.RawMessage{}}, nil
		},
	}

	_, _, err := MakeSearchIndexHandler(vc)(context.Background(), nil, searchIndexArgs{
		Index:       "threat-actors",
		ThreatActor: "UNC2630",
		MitreID:     "G0013",
		MispID:      "3570552c-c46f-428e-9472-744a14e6ece7",
		Ransomware:  "Cactus",
		Botnet:      "Fbot",
		JVNDB:       "JVNDB-2025-007355",
	})
	require.NoError(t, err)

	assert.Equal(t, "threat-actors", got.Index)
	assert.Equal(t, "UNC2630", got.ThreatActor)
	assert.Equal(t, "G0013", got.MitreID)
	assert.Equal(t, "3570552c-c46f-428e-9472-744a14e6ece7", got.MispID)
	assert.Equal(t, "Cactus", got.Ransomware)
	assert.Equal(t, "Fbot", got.Botnet)
	assert.Equal(t, "JVNDB-2025-007355", got.JVNDB)
}

// The product indices have dedicated tools that expose host and network filters
// this one cannot, so the description has to send callers there rather than leaving
// them to discover the worse path.
func TestSearchIndexTool_PointsAtTheProductTools(t *testing.T) {
	for _, tool := range []string{"search_ip_intel", "search_target_intel", "search_canaries"} {
		assert.Contains(t, SearchIndexTool.Description, tool)
	}
}
