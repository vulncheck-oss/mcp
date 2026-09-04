package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type identifyComponentArgs struct {
	Vendor  string `json:"vendor"            jsonschema:"Vendor or manufacturer name, e.g. 'microsoft corporation'"`
	Product string `json:"product"           jsonschema:"Product name, e.g. 'office 2016'"`
	Version string `json:"version,omitempty" jsonschema:"Version string, e.g. '16.0.1'"`
}

// identifyComponentResult wraps the matches in an envelope rather than marshalling the
// bare array the API hands back.
//
// Two reasons, and the wrapper predates the second. Nothing can be a sibling of a JSON
// array, so a bare array is the one shape that cannot carry the response_size report inside
// itself; wrapping it means capResult has one shape to serve instead of two, and the report
// always travels with the data it describes. The tool now also reports returned and total
// like every other, which a bare array has nowhere to put.
//
// `data` rather than `matches` because that is where every other tool puts its rows.
type identifyComponentResult struct {
	envelope
	Data []client.IdentifyResult `json:"data"`
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

		// This tool does not paginate, so total is the row count rather than a larger
		// matching set. That is truthful, and it stays useful: capResult lowers returned
		// if it trims rows, leaving total > returned to report the withholding.
		return capResult(identifyComponentResult{
			envelope: newEnvelope(len(results), len(results), ""),
			Data:     results,
		})
	}
}
