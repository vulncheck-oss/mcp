package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchCPEArgs struct {
	Part           string `json:"part,omitempty"            jsonschema:"CPE part (a=application, o=operating system, h=hardware)"`
	Vendor         string `json:"vendor,omitempty"          jsonschema:"CPE vendor"`
	Product        string `json:"product,omitempty"         jsonschema:"CPE product"`
	Version        string `json:"version,omitempty"         jsonschema:"CPE version (supports trailing wildcards, e.g. '8.0.*')"`
	VulnerableOnly bool   `json:"vulnerable_only,omitempty" jsonschema:"When true, return only CPEs confirmed vulnerable (default false)"`
}

var SearchCPETool = &mcp.Tool{
	Name:        "search_cpe",
	Title:       "Search CPE",
	Description: "Search for CPEs by component fields (vendor, product, version, part) and return matching CPEs with their associated CVEs.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchCPE(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchCPETool, MakeSearchCPEHandler(vc))
}

func MakeSearchCPEHandler(vc client.Client) mcp.ToolHandlerFor[searchCPEArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchCPEArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchCPE(ctx, client.SearchCPEQuery{
			Part:           args.Part,
			Vendor:         args.Vendor,
			Product:        args.Product,
			Version:        args.Version,
			VulnerableOnly: args.VulnerableOnly,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching CPE: %w", err)
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
