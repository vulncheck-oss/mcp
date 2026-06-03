package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchCVEArgs struct {
	CVE         string `json:"cve"                    jsonschema:"required,CVE ID to search across all indices, e.g. 'CVE-2021-44228'"`
	Limit       int32  `json:"limit,omitempty"        jsonschema:"Results per page (default: 1)"`
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

func registerSearchCVE(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchCVETool, MakeSearchCVEHandler(vc))
}

func MakeSearchCVEHandler(vc client.Client) mcp.ToolHandlerFor[searchCVEArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchCVEArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 1
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

		out, err := json.Marshal(result)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
