package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchNVDCVEHistoryArgs struct {
	CVEID           string `json:"cve_id,omitempty"            jsonschema:"Only changes to this CVE, e.g. 'CVE-2021-44228'"`
	EventName       string `json:"event_name,omitempty"        jsonschema:"Only changes of this type, e.g. 'Initial Analysis', 'Reanalysis', 'CVE Modified', 'CWE Remap', 'CVE CISA KEV Update', 'CVE Rejected'"`
	ChangeStartDate string `json:"change_start_date,omitempty" jsonschema:"Changed on or after. Requires change_end_date"`
	ChangeEndDate   string `json:"change_end_date,omitempty"   jsonschema:"Changed on or before. Requires change_start_date"`
	Limit           int32  `json:"limit,omitempty"             jsonschema:"Results per page (default 20, max 100)"`
	StartCursor     bool   `json:"start_cursor,omitempty"      jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor          string `json:"cursor,omitempty"            jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchNVDCVEHistoryTool = &mcp.Tool{
	Name:  "search_nvd_cve_history",
	Title: "Search NVD CVE History",
	Description: "Search NVD's change history for CVEs: each event in which NVD changed a record (initial analysis, " +
		"reanalysis, CVSS and CWE changes, CPE deprecation remaps, KEV updates, rejections), with the old and new " +
		"values. Answers when and how NVD's assessment of a CVE changed. For community tokens this is the only route " +
		"to NVD's change history. " + nvdDateClause + " Supports cursor-based pagination. " + nvdCommunityClause,
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type searchNVDCVEHistoryResult struct {
	envelope
	Data []vulncheck.RestNvdChange `json:"data"`
}

func registerSearchNVDCVEHistory(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchNVDCVEHistoryTool, MakeSearchNVDCVEHistoryHandler(vc))
}

func MakeSearchNVDCVEHistoryHandler(vc client.Client) mcp.ToolHandlerFor[searchNVDCVEHistoryArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchNVDCVEHistoryArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchNVDCVEHistory(ctx, client.NVDCVEHistoryQuery{
			CVEID:           args.CVEID,
			EventName:       args.EventName,
			ChangeStartDate: args.ChangeStartDate,
			ChangeEndDate:   args.ChangeEndDate,
			Page:            nvdPage(nvdLimit(args.Limit, 20, 100), args.StartCursor, args.Cursor),
		})
		if err != nil {
			return nil, nil, err
		}

		return capResult(searchNVDCVEHistoryResult{
			envelope: nvdCursorEnvelope(len(result.Data), result.Total, result.NextCursor, args.Cursor),
			Data:     result.Data,
		})
	}
}
