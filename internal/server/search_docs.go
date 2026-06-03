package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var SearchDocsTool = &mcp.Tool{
	Name:        "search_docs",
	Title:       "Search Docs",
	Description: "Fetch the VulnCheck documentation index. Returns a list of all available documentation pages and their URLs. Use get_doc to retrieve the content of a specific page.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchDocs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchDocsTool, MakeSearchDocsHandler(vc))
}

func MakeSearchDocsHandler(vc client.Client) mcp.ToolHandlerFor[struct{}, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchDocs(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("searching docs: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, nil, nil
	}
}
