package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchCPEArgs struct {
	Part           string `json:"part,omitempty"            jsonschema:"CPE part (a=application, o=operating system, h=hardware)"`
	Vendor         string `json:"vendor,omitempty"          jsonschema:"CPE vendor"`
	Product        string `json:"product,omitempty"         jsonschema:"CPE product"`
	Version        string `json:"version,omitempty"         jsonschema:"CPE version (supports trailing wildcards, e.g. '8.0.*')"`
	VulnerableOnly bool   `json:"vulnerable_only,omitempty" jsonschema:"When true, each CPE lists only the CVEs for which it is a vulnerable configuration, rather than every CVE referencing it. This does NOT reduce the set of CPEs returned — the row count is the same either way (default false)"`
}

var SearchCPETool = &mcp.Tool{
	Name:  "search_cpe",
	Title: "Search CPE",
	Description: "Search for CPEs by component fields (vendor, product, version, part) and return matching CPEs with their associated CVEs. " +
		"vulnerable_only narrows the CVEs listed against each CPE, not the CPEs returned; there is no filter here for \"only vulnerable components\".",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// noPagingRouteNote is this tool's route clause, and it is the one that says there is no
// route. The upstream endpoint caps a page at 100 CPEs and does accept a page parameter,
// but the SDK request type exposes neither page nor limit, so this tool cannot send them —
// and partialSetNote on its own would point a caller at a page 2 it has no way to fetch.
const noPagingRouteNote = "this tool cannot reach the rest: it has no page, limit or cursor " +
	"argument, and the upstream page is capped at 100 CPEs. To enumerate a vendor or product " +
	"use get_cpe_cves with a wildcard CPE, or a backup of the index"

// searchCPEResult carries the matches under the shared envelope. This endpoint does not
// paginate through this tool, so there is no cursor.
type searchCPEResult struct {
	envelope
	Data []vulncheck.SearchResponseDataOut `json:"data"`
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

		response := searchCPEResult{
			envelope: newEnvelope(len(result.Data), result.Total, ""),
			Data:     result.Data,
		}
		if response.Total > response.Returned {
			response.Notes = append(response.Notes, partialSetNote, noPagingRouteNote)
		}

		return capResult(response)
	}
}
