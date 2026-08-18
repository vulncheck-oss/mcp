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
	Name:  "list_indices",
	Title: "List Indices",
	Description: "List VulnCheck index names. Call this first to discover which index names exist. " +
		"Returns names only unless a search narrows the set, since the full catalogue is large; descriptions can be requested explicitly. " +
		"Use describe_index to find out which filters an index accepts and which tool to query it with.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type listIndicesArgs struct {
	Search             string `json:"search,omitempty"              jsonschema:"Optional filter — return only indices whose name or description contains this string (case-insensitive)"`
	IncludeDescription *bool  `json:"include_description,omitempty" jsonschema:"Include each index's description. Omitted by default because the full catalogue is large, and included automatically when search narrows it. Set true to force, false to suppress"`
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

		// Descriptions are the bulk of this response. A search narrows the set enough
		// that they are worth including, so the default follows the caller's intent
		// rather than making them ask twice.
		withDescription := args.Search != ""
		if args.IncludeDescription != nil {
			withDescription = *args.IncludeDescription
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

		if !withDescription {
			for i := range entries {
				entries[i].Description = ""
			}
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
