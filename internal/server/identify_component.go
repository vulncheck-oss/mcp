package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type identifyComponentArgs struct {
	Vendor  string `json:"vendor"            jsonschema:"Vendor or manufacturer name, e.g. 'microsoft corporation'"`
	Product string `json:"product"           jsonschema:"Product name, e.g. 'office 2016'"`
	Version string `json:"version,omitempty" jsonschema:"Version string, e.g. '16.0.1'"`
}

var IdentifyComponentTool = &mcp.Tool{
	Name:        "identify_component",
	Title:       "Identify Component",
	Description: "Convert a vendor, product, and optional version into best-match CPE and PURL identifiers with confidence levels.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerIdentifyComponent(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, IdentifyComponentTool, MakeIdentifyComponentHandler(vc))
}

func MakeIdentifyComponentHandler(vc client.Client) mcp.ToolHandlerFor[identifyComponentArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args identifyComponentArgs) (*mcp.CallToolResult, any, error) {
		results, err := vc.IdentifyComponent(ctx, args.Vendor, args.Product, args.Version)
		if err != nil {
			return nil, nil, fmt.Errorf("identifying component %q %q: %w", args.Vendor, args.Product, err)
		}

		out, err := json.Marshal(results)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
