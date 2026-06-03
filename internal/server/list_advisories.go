package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var ListAdvisoriesTool = &mcp.Tool{
	Name:        "v4_list_advisories",
	Title:       "List Advisories",
	Description: "List all available VulnCheck advisory feeds. Call this first to discover which advisory names can be passed to v4_search_advisory.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerListAdvisories(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListAdvisoriesTool, MakeListAdvisoriesHandler(vc))
}

func MakeListAdvisoriesHandler(vc client.Client) mcp.ToolHandlerFor[struct{}, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		entries, err := vc.ListAdvisories(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing advisories: %w", err)
		}

		out, err := json.Marshal(listEntriesResult{Data: entries, Total: len(entries)})
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
