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
			name:       "zero limit defaults to 5",
			args:       searchCVEArgs{CVE: "CVE-2099-99999"},
			clientResp: &client.SearchCVEResult{Data: []vulncheck.IndexCveSearchHit{}, Total: 0},
			wantQuery:  client.SearchCVEQuery{CVE: "CVE-2099-99999", Limit: 5},
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

// TestSearchCVE_RouteNoteOnlyWhenNoWalkIsUnderWay pins the gate on cursorRouteNote.
//
// The last page of a cursor walk carries no next_cursor, exactly like a first page that was
// never asked for one. Without checking the request, a caller holding the final page is told
// to "set start_cursor true on the first call" — sent back to the beginning of a walk it has
// just finished. The index tools gate the same way, on CursorContinuation.
func TestSearchCVE_RouteNoteOnlyWhenNoWalkIsUnderWay(t *testing.T) {
	hits := make([]vulncheck.IndexCveSearchHit, 5)
	mock := &mockClient{
		searchCVEFn: func(context.Context, client.SearchCVEQuery) (*client.SearchCVEResult, error) {
			// Partial, and no cursor coming back: the shape shared by a first page and
			// a last page.
			return &client.SearchCVEResult{Data: hits, Total: 3_501}, nil
		},
	}

	tests := []struct {
		name      string
		args      searchCVEArgs
		wantRoute bool
	}{
		{
			name:      "no walk under way: name the route",
			args:      searchCVEArgs{CVE: "CVE-2021-44228"},
			wantRoute: true,
		},
		{
			name:      "last page of a walk: the caller already knows the route",
			args:      searchCVEArgs{CVE: "CVE-2021-44228", Cursor: "abc"},
			wantRoute: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runTool(t, mock, func(vc client.Client) toolCall {
				return call(MakeSearchCVEHandler(vc), tt.args)
			})

			var got searchCVEResult
			require.NoError(t, json.Unmarshal([]byte(payloadText(t, result)), &got))

			assert.Contains(t, got.Notes, partialSetNote, "the set is partial either way")
			if tt.wantRoute {
				assert.Contains(t, got.Notes, cursorRouteNote)
			} else {
				assert.NotContains(t, got.Notes, cursorRouteNote)
			}
		})
	}
}
