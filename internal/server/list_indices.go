package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var ListIndicesTool = &mcp.Tool{
	Name:        "list_indices",
	Title:       "List Indices",
	Description: "List all VulnCheck indices. Call this first to discover which index names can be passed to search_index. Accepts an optional 'search' parameter to filter results by name or description.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type listIndicesArgs struct {
	Search string `json:"search,omitempty" jsonschema:"Optional filter — return only indices whose name or description contains this string (case-insensitive)"`
}

type listEntriesResult struct {
	Data  []client.Entry `json:"data"`
	Total int            `json:"total"`
}

func registerListIndices(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListIndicesTool, MakeListIndicesHandler(vc))
}

func MakeListIndicesHandler(vc client.Client) mcp.ToolHandlerFor[listIndicesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args listIndicesArgs) (*mcp.CallToolResult, any, error) {
		entries, err := vc.ListIndices(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing indices: %w", err)
		}

		if args.Search != "" {
			q := strings.ToLower(args.Search)
			filtered := entries[:0]
			for _, e := range entries {
				if strings.Contains(strings.ToLower(e.Name), q) || strings.Contains(strings.ToLower(e.Description), q) {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}

		out, err := json.Marshal(listEntriesResult{
			Data:  entries,
			Total: len(entries),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
