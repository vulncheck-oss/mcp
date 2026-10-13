package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchNVDCPEsArgs struct {
	CPENameID        string `json:"cpe_name_id,omitempty"         jsonschema:"A single dictionary entry by its NVD UUID"`
	CPEMatchString   string `json:"cpe_match_string,omitempty"    jsonschema:"A CPE 2.3 name or prefix, e.g. 'cpe:2.3:a:apache:log4j'. CPE 2.2 URIs are not supported"`
	MatchCriteriaID  string `json:"match_criteria_id,omitempty"   jsonschema:"Only the CPE names this match criteria UUID resolves to"`
	LastModStartDate string `json:"last_mod_start_date,omitempty" jsonschema:"Last modified on or after. Requires last_mod_end_date"`
	LastModEndDate   string `json:"last_mod_end_date,omitempty"   jsonschema:"Last modified on or before. Requires last_mod_start_date"`
	Limit            int32  `json:"limit,omitempty"               jsonschema:"Results per page (default 20, max 100)"`
	StartCursor      bool   `json:"start_cursor,omitempty"        jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor           string `json:"cursor,omitempty"              jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchNVDCPEsTool = &mcp.Tool{
	Name:  "search_nvd_cpes",
	Title: "Search NVD CPE Dictionary",
	Description: "Search NVD's CPE dictionary: official CPE 2.3 names with their titles, references and deprecations. " +
		"Match by a CPE prefix such as cpe:2.3:a:apache:log4j, by NVD's cpeNameId, or by the match criteria a name " +
		"falls under. This is the dictionary entry for a product, not its vulnerabilities: for which CVEs affect a " +
		"CPE use get_cpe_cves. " + nvdDateClause + " Supports cursor-based pagination. " + nvdCommunityClause,
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type searchNVDCPEsResult struct {
	envelope
	Data []vulncheck.NvdcpesNvdCpe `json:"data"`
}

func registerSearchNVDCPEs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchNVDCPEsTool, MakeSearchNVDCPEsHandler(vc))
}

func MakeSearchNVDCPEsHandler(vc client.Client) mcp.ToolHandlerFor[searchNVDCPEsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchNVDCPEsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchNVDCPEs(ctx, client.NVDCPEsQuery{
			CPENameID:        args.CPENameID,
			CPEMatchString:   args.CPEMatchString,
			MatchCriteriaID:  args.MatchCriteriaID,
			LastModStartDate: args.LastModStartDate,
			LastModEndDate:   args.LastModEndDate,
			Page:             nvdPage(nvdLimit(args.Limit, 20, 100), args.StartCursor, args.Cursor),
		})
		if err != nil {
			return nil, nil, err
		}

		return capResult(searchNVDCPEsResult{
			envelope: nvdCursorEnvelope(len(result.Data), result.Total, result.NextCursor, args.Cursor),
			Data:     result.Data,
		})
	}
}
