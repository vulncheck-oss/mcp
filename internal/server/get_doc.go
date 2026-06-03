package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getDocArgs struct {
	URL string `json:"url" jsonschema:"required,Full URL of the documentation page to fetch, e.g. 'https://docs.vulncheck.com/raw/getting-started/api-tokens.md' — use search_docs to discover valid URLs"`
}

var GetDocTool = &mcp.Tool{
	Name:        "get_doc",
	Title:       "Get Doc",
	Description: "Fetch the raw markdown content of a VulnCheck documentation page. Use search_docs first to discover available page URLs.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerGetDoc(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, GetDocTool, MakeGetDocHandler(vc))
}

func MakeGetDocHandler(vc client.Client) mcp.ToolHandlerFor[getDocArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args getDocArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.GetDoc(ctx, args.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("getting doc: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, nil, nil
	}
}
