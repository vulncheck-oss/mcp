package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getCPECVEsArgs struct {
	CPE            string `json:"cpe"                        jsonschema:"CPE 2.3 string, e.g. 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'"`
	VulnerableOnly bool   `json:"vulnerable_only,omitempty"  jsonschema:"When true, return only CVEs where the CPE is confirmed vulnerable (default false)"`
}

var GetCPECVEsTool = &mcp.Tool{
	Name:        "get_cpe_cves",
	Title:       "Get CPE CVEs",
	Description: "Return all CVE IDs associated with a CPE 2.3 string. Optionally restrict to CVEs where the CPE is confirmed vulnerable.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type getCPECVEsResult struct {
	CPE   string   `json:"cpe"`
	CVEs  []string `json:"cves"`
	Total int      `json:"total"`
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

		out, err := json.Marshal(getCPECVEsResult{
			CPE:   args.CPE,
			CVEs:  result.CVEs,
			Total: result.Total,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
