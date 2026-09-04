package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchPURLsArgs struct {
	PURLs []string `json:"purls" jsonschema:"Package URLs, e.g. 'pkg:hex/coherence@0.1.2'"`
}

var SearchPURLsTool = &mcp.Tool{
	Name:        "search_purls",
	Title:       "Search Package URLs",
	Description: "Return vulnerability findings for one or more Package URLs (PURLs). Each result includes associated CVEs and vulnerability details.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// searchPURLsResult carries the findings under the shared envelope.
//
// It also fixes a defect of returning the client result directly: that type tags Data
// `omitempty`, so a query matching nothing dropped the field altogether and "no findings"
// was indistinguishable from "the field is missing". Here data is always present.
type searchPURLsResult struct {
	envelope
	Data []vulncheck.PurlBatchVulnFinding `json:"data"`
}

func registerSearchPURLs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchPURLsTool, MakeSearchPURLsHandler(vc))
}

func MakeSearchPURLsHandler(vc client.Client) mcp.ToolHandlerFor[searchPURLsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchPURLsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchPURLs(ctx, args.PURLs)
		if err != nil {
			return nil, nil, fmt.Errorf("searching PURLs: %w", err)
		}

		return capResult(searchPURLsResult{
			envelope: newEnvelope(len(result.Data), result.Total, ""),
			Data:     result.Data,
		})
	}
}
