package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getRulesArgs struct {
	Type string `json:"type"          jsonschema:"Type of ruleset to retrieve: 'suricata' or 'snort'"`
	CVE  string `json:"cve,omitempty" jsonschema:"Optional CVE ID filter — return only rules whose text contains this CVE ID (case-insensitive). Example: CVE-2021-44228"`
}

var GetRulesTool = &mcp.Tool{
	Name:        "get_rules",
	Title:       "Get Rules",
	Description: "Retrieve initial-access detection rules by type. Supported types: 'suricata', 'snort'. Accepts an optional 'cve' parameter to filter rules to those containing a specific CVE ID.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerGetRules(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, GetRulesTool, MakeGetRulesHandler(vc))
}

func MakeGetRulesHandler(vc client.Client) mcp.ToolHandlerFor[getRulesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args getRulesArgs) (*mcp.CallToolResult, any, error) {
		rules, err := vc.GetRules(ctx, args.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("getting rules: %w", err)
		}

		if args.CVE != "" {
			q := strings.ToLower(args.CVE)
			var kept []string
			for line := range strings.SplitSeq(rules, "\n") {
				if strings.Contains(strings.ToLower(line), q) {
					kept = append(kept, line)
				}
			}
			rules = strings.Join(kept, "\n")
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: rules}},
		}, nil, nil
	}
}
