package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchNVDCPEMatchArgs struct {
	CVEID            string `json:"cve_id,omitempty"              jsonschema:"Only the match criteria in this CVE's configurations, e.g. 'CVE-2021-44228'"`
	MatchCriteriaID  string `json:"match_criteria_id,omitempty"   jsonschema:"A single match criteria by its NVD UUID"`
	LastModStartDate string `json:"last_mod_start_date,omitempty" jsonschema:"Last modified on or after. Requires last_mod_end_date"`
	LastModEndDate   string `json:"last_mod_end_date,omitempty"   jsonschema:"Last modified on or before. Requires last_mod_start_date"`
	Limit            int32  `json:"limit,omitempty"               jsonschema:"Results per page (default 10, max 50). Criteria can expand to many CPE names, so keep this small"`
	StartCursor      bool   `json:"start_cursor,omitempty"        jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor           string `json:"cursor,omitempty"              jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchNVDCPEMatchTool = &mcp.Tool{
	Name:  "search_nvd_cpe_match",
	Title: "Search NVD CPE Match Criteria",
	Description: "Search NVD's CPE match criteria: the CPE patterns and version ranges in a CVE's configurations, each " +
		"expanded to the concrete CPE names it covers. Answers which exact product versions NVD's criteria for a CVE " +
		"resolve to. For community tokens this is the only route to NVD's match criteria. " + nvdDateClause +
		" Supports cursor-based pagination. " + nvdCommunityClause,
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type searchNVDCPEMatchResult struct {
	envelope
	Data []vulncheck.NvdcpematchNvdMatchString `json:"data"`
}

func registerSearchNVDCPEMatch(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchNVDCPEMatchTool, MakeSearchNVDCPEMatchHandler(vc))
}

func MakeSearchNVDCPEMatchHandler(vc client.Client) mcp.ToolHandlerFor[searchNVDCPEMatchArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchNVDCPEMatchArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchNVDCPEMatch(ctx, client.NVDCPEMatchQuery{
			CVEID:            args.CVEID,
			MatchCriteriaID:  args.MatchCriteriaID,
			LastModStartDate: args.LastModStartDate,
			LastModEndDate:   args.LastModEndDate,
			Page:             nvdPage(nvdLimit(args.Limit, 10, 50), args.StartCursor, args.Cursor),
		})
		if err != nil {
			return nil, nil, err
		}

		return capResult(searchNVDCPEMatchResult{
			envelope: nvdCursorEnvelope(len(result.Data), result.Total, result.NextCursor, args.Cursor),
			Data:     result.Data,
		})
	}
}
