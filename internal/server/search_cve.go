package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchCVEArgs struct {
	CVE         string `json:"cve"                    jsonschema:"required,CVE ID to search across all indices, e.g. 'CVE-2021-44228'"`
	Limit       int32  `json:"limit,omitempty"        jsonschema:"Results per page (max 10). Use cursor-based pagination for additional results."`
	StartCursor bool   `json:"start_cursor,omitempty" jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor      string `json:"cursor,omitempty"       jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchCVETool = &mcp.Tool{
	Name:        "search_cve",
	Title:       "Search CVE",
	Description: "Search all VulnCheck indices for a CVE ID. Returns matching records aggregated across advisories, exploits, threat intelligence, and vulnerability databases. Supports cursor-based pagination.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// searchCVEResult carries the hits under the shared envelope. The client result has the
// core fields already, but returning it directly left the tool with no notes field and no
// returned count, so a trimmed page could not say how much of it was actually present.
type searchCVEResult struct {
	envelope
	Data []vulncheck.IndexCveSearchHit `json:"data"`
}

func registerSearchCVE(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchCVETool, MakeSearchCVEHandler(vc))
}

func MakeSearchCVEHandler(vc client.Client) mcp.ToolHandlerFor[searchCVEArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchCVEArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 5
		}
		if limit > 10 {
			limit = 10
		}
		result, err := vc.SearchCVE(ctx, client.SearchCVEQuery{
			CVE:         args.CVE,
			Limit:       limit,
			StartCursor: args.StartCursor,
			Cursor:      args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching CVE: %w", err)
		}

		response := searchCVEResult{
			envelope: newEnvelope(len(result.Data), int(result.Total), result.NextCursor),
			Data:     result.Data,
		}
		// Without this the tool reports 5 rows against a total of 3,501 and says nothing
		// about either fact — neither that the rows are a fraction of the match, nor
		// that a cursor is how to see the rest.
		if response.Total > response.Returned {
			response.Notes = append(response.Notes, partialSetNote)
			if response.NextCursor == "" && args.Cursor == "" {
				response.Notes = append(response.Notes, cursorRouteNote)
			}
		}

		return capResult(response)
	}
}
