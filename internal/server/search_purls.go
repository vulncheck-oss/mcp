package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchPURLsArgs struct {
	PURLs []string `json:"purls" jsonschema:"Package URLs, e.g. 'pkg:hex/coherence@0.1.2'"`
}

var SearchPURLsTool = &mcp.Tool{
	Name:        "search_purls",
	Title:       "Search Package URLs",
	Description: "Return vulnerability findings for one or more Package URLs (PURLs). Each result includes associated CVEs and vulnerability details.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchPURLs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchPURLsTool, MakeSearchPURLsHandler(vc))
}

func MakeSearchPURLsHandler(vc client.Client) mcp.ToolHandlerFor[searchPURLsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchPURLsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchPURLs(ctx, args.PURLs)
		if err != nil {
			return nil, nil, fmt.Errorf("searching PURLs: %w", err)
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
