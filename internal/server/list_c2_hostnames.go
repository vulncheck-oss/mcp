package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var ListC2HostnamesTool = &mcp.Tool{
	Name:        "list_c2_hostnames",
	Title:       "List C2 Hostnames",
	Description: "Retrieve the list of VulnCheck C2 hostnames. Useful for identifying command-and-control infrastructure in protective DNS services and denylists. Accepts an optional 'search' parameter to look up a specific hostname.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type listC2HostnamesArgs struct {
	Search string `json:"search,omitempty" jsonschema:"Optional filter — return only hostnames containing this string (case-insensitive). Example: evil.example.com"`
}

func registerListC2Hostnames(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListC2HostnamesTool, MakeListC2HostnamesHandler(vc))
}

func MakeListC2HostnamesHandler(vc client.Client) mcp.ToolHandlerFor[listC2HostnamesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args listC2HostnamesArgs) (*mcp.CallToolResult, any, error) {
		hostnames, err := vc.ListC2Hostnames(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing C2 hostnames: %w", err)
		}

		if args.Search != "" {
			q := strings.ToLower(args.Search)
			var kept []string
			for line := range strings.SplitSeq(hostnames, "\n") {
				if strings.Contains(strings.ToLower(line), q) {
					kept = append(kept, line)
				}
			}
			hostnames = strings.Join(kept, "\n")
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: hostnames}},
		}, nil, nil
	}
}
