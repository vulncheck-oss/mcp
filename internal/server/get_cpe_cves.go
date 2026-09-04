package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getCPECVEsArgs struct {
	CPE            string `json:"cpe"                        jsonschema:"CPE 2.3 string, e.g. 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'. Any attribute accepts '*' and '?' wildcards, e.g. 'cpe:2.3:a:apache:log4j*:*:*:*:*:*:*:*'"`
	VulnerableOnly bool   `json:"vulnerable_only,omitempty"  jsonschema:"When true, return only CVEs where the CPE is confirmed vulnerable (default false)"`
}

var GetCPECVEsTool = &mcp.Tool{
	Name:  "get_cpe_cves",
	Title: "Get CPE CVEs",
	Description: "Return all CVE IDs associated with a CPE 2.3 string. Optionally restrict to CVEs where the CPE is confirmed vulnerable. " +
		"Any attribute accepts '*' and '?' wildcards, so a trailing wildcard on the product covers every product sharing that prefix in one call — " +
		"prefer this over search_cpe when exploring a vendor: search_cpe returns at most 100 CPEs per call with no way to page to the rest, and its response can still reach tens of megabytes because each CPE carries its full CVE list. " +
		"Wildcarding both vendor and product is unbounded and should be avoided.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// getCPECVEsResult returns the CVE IDs under `data`, not `cves`.
//
// This tool used to be the only one naming its rows after their content. `data` is where
// every other tool puts them — see identifyComponentResult, which made the same choice for
// the same reason — and a caller should not have to know which tool it called to find the
// rows. The list is still flat CVE ID strings; only the field name changed.
type getCPECVEsResult struct {
	envelope
	CPE  string   `json:"cpe"`
	Data []string `json:"data"`
}

func registerGetCPECVEs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, GetCPECVEsTool, MakeGetCPECVEsHandler(vc))
}

func MakeGetCPECVEsHandler(vc client.Client) mcp.ToolHandlerFor[getCPECVEsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args getCPECVEsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.GetCPECVEs(ctx, args.CPE, args.VulnerableOnly)
		if err != nil {
			return nil, nil, fmt.Errorf("getting CPE CVEs: %w", err)
		}

		return capResult(getCPECVEsResult{
			envelope: newEnvelope(len(result.CVEs), result.Total, ""),
			CPE:      args.CPE,
			Data:     result.CVEs,
		})
	}
}
