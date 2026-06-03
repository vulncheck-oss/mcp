package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var ListC2TagsTool = &mcp.Tool{
	Name:        "list_c2_tags",
	Title:       "List C2 Tags",
	Description: "Retrieve the list of VulnCheck C2 IP addresses. Useful for identifying command-and-control infrastructure in block lists or firewall rules. Accepts an optional 'search' parameter to look up a specific IP address.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type listC2TagsArgs struct {
	Search string `json:"search,omitempty" jsonschema:"Optional filter — return only IP addresses containing this string (case-insensitive). Example: 192.168.1"`
}

func registerListC2Tags(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListC2TagsTool, MakeListC2TagsHandler(vc))
}

func MakeListC2TagsHandler(vc client.Client) mcp.ToolHandlerFor[listC2TagsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args listC2TagsArgs) (*mcp.CallToolResult, any, error) {
		tags, err := vc.ListC2Tags(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing C2 tags: %w", err)
		}

		if args.Search != "" {
			q := strings.ToLower(args.Search)
			var kept []string
			for line := range strings.SplitSeq(tags, "\n") {
				if strings.Contains(strings.ToLower(line), q) {
					kept = append(kept, line)
				}
			}
			tags = strings.Join(kept, "\n")
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: tags}},
		}, nil, nil
	}
}
