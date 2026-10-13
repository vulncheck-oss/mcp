package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchNVDSourcesArgs struct {
	SourceIdentifier string `json:"source_identifier,omitempty"   jsonschema:"Only the source with this identifier, e.g. 'cve@mitre.org'"`
	LastModStartDate string `json:"last_mod_start_date,omitempty" jsonschema:"Last modified on or after. Requires last_mod_end_date"`
	LastModEndDate   string `json:"last_mod_end_date,omitempty"   jsonschema:"Last modified on or before. Requires last_mod_start_date"`
	Limit            int32  `json:"limit,omitempty"               jsonschema:"Results per page (default 20, max 100)"`
	StartIndex       int32  `json:"start_index,omitempty"         jsonschema:"Zero-based offset of the first result, for the next page"`
}

var SearchNVDSourcesTool = &mcp.Tool{
	Name:  "search_nvd_sources",
	Title: "Search NVD Sources",
	Description: "List the organisations NVD records as data sources (CNAs, ADPs and NVD itself), with their " +
		"identifiers and the CVSS and CWE data NVD accepts from each. Use to resolve a sourceIdentifier such as " +
		"cve@mitre.org to an organisation. For community tokens this is the only route to NVD's source list. " +
		nvdDateClause + " Pages by start_index; there is no cursor. " + nvdCommunityClause,
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type searchNVDSourcesResult struct {
	envelope
	Data []vulncheck.NvdsourceNvdSource `json:"data"`
}

func registerSearchNVDSources(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchNVDSourcesTool, MakeSearchNVDSourcesHandler(vc))
}

func MakeSearchNVDSourcesHandler(vc client.Client) mcp.ToolHandlerFor[searchNVDSourcesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchNVDSourcesArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchNVDSources(ctx, client.NVDSourcesQuery{
			SourceIdentifier: args.SourceIdentifier,
			LastModStartDate: args.LastModStartDate,
			LastModEndDate:   args.LastModEndDate,
			Page:             client.NVDPage{Limit: nvdLimit(args.Limit, 20, 100), StartIndex: args.StartIndex},
		})
		if err != nil {
			return nil, nil, err
		}

		env := newEnvelope(len(result.Data), result.Total, "")
		if int(args.StartIndex)+env.Returned < env.Total {
			env.Notes = append(env.Notes, partialSetNote, nvdStartIndexRouteNote)
		}

		return capResult(searchNVDSourcesResult{envelope: env, Data: result.Data})
	}
}
