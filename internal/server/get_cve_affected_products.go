package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getCVEAffectedProductsArgs struct {
	CVE string `json:"cve" jsonschema:"required,CVE ID to resolve to affected software, e.g. 'CVE-2021-44228'"`
}

var GetCVEAffectedProductsTool = &mcp.Tool{
	Name:  "get_cve_affected_products",
	Title: "Get CVE Affected Products",
	Description: "Resolve a CVE ID to the software it affects: vendor and product pairs with the vulnerable version ranges, extracted from NVD CPE configurations. " +
		"Use this for any question about which products, vendors, or versions a CVE affects. search_cve does not answer it: it returns a page of the highest-scoring records across every index, " +
		"which for CVE-2024-21762 is 10 of 182 hits and includes none of the NVD records that carry the configurations. " +
		"Entries a configuration marks non-vulnerable are reported separately as platforms, meaning the environment a vulnerable component runs on rather than the component to patch. " +
		"Each entry names the sources it came from, since NIST and VulnCheck sometimes spell the same vendor differently. " +
		"When a CVE carries no CPE data at all, common for package-ecosystem advisories (npm, PyPI, Go), the response says so in a note rather than returning a bare empty list.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerGetCVEAffectedProducts(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, GetCVEAffectedProductsTool, MakeGetCVEAffectedProductsHandler(vc))
}

func MakeGetCVEAffectedProductsHandler(vc client.Client) mcp.ToolHandlerFor[getCVEAffectedProductsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args getCVEAffectedProductsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.GetCVEAffectedProducts(ctx, args.CVE)
		if err != nil {
			return nil, nil, fmt.Errorf("getting affected products: %w", err)
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
