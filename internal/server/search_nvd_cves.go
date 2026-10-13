package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type searchNVDCVEsArgs struct {
	CVEID              string `json:"cve_id,omitempty"               jsonschema:"A single CVE ID, e.g. 'CVE-2021-44228'"`
	CPEName            string `json:"cpe_name,omitempty"             jsonschema:"A complete CPE 2.3 name; returns CVEs whose configurations match it"`
	IsVulnerable       bool   `json:"is_vulnerable,omitempty"        jsonschema:"Only CVEs where cpe_name is marked vulnerable. Requires cpe_name"`
	VirtualMatchString string `json:"virtual_match_string,omitempty" jsonschema:"A CPE 2.3 name or prefix (at least part and vendor, e.g. 'cpe:2.3:a:apache') matched against configuration criteria"`
	VersionStart       string `json:"version_start,omitempty"        jsonschema:"Lower version bound. Requires virtual_match_string and version_start_type"`
	VersionStartType   string `json:"version_start_type,omitempty"   jsonschema:"Whether version_start is inclusive: 'including' or 'excluding'"`
	VersionEnd         string `json:"version_end,omitempty"          jsonschema:"Upper version bound. Requires virtual_match_string and version_end_type"`
	VersionEndType     string `json:"version_end_type,omitempty"     jsonschema:"Whether version_end is inclusive: 'including' or 'excluding'"`
	CVETag             string `json:"cve_tag,omitempty"              jsonschema:"Only CVEs with this tag: 'disputed', 'unsupported-when-assigned' or 'exclusively-hosted-service'"`
	HasKEV             bool   `json:"has_kev,omitempty"              jsonschema:"Only CVEs in the CISA KEV catalog"`
	NoRejected         bool   `json:"no_rejected,omitempty"          jsonschema:"Exclude rejected CVEs"`
	PubStartDate       string `json:"pub_start_date,omitempty"       jsonschema:"Published on or after. Requires pub_end_date"`
	PubEndDate         string `json:"pub_end_date,omitempty"         jsonschema:"Published on or before. Requires pub_start_date"`
	LastModStartDate   string `json:"last_mod_start_date,omitempty"  jsonschema:"Last modified on or after. Requires last_mod_end_date"`
	LastModEndDate     string `json:"last_mod_end_date,omitempty"    jsonschema:"Last modified on or before. Requires last_mod_start_date"`
	SourceIdentifier   string `json:"source_identifier,omitempty"    jsonschema:"Only CVEs from this source, e.g. 'cve@mitre.org'"`
	Limit              int32  `json:"limit,omitempty"                jsonschema:"Results per page (default 5, max 20). Records are large, so keep this small"`
	StartCursor        bool   `json:"start_cursor,omitempty"         jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor             string `json:"cursor,omitempty"               jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchNVDCVEsTool = &mcp.Tool{
	Name:  "search_nvd_cves",
	Title: "Search NVD CVEs",
	Description: "Search CVE records as the NVD API 2.0 publishes them, through VulnCheck's NVD-compatible endpoint. " +
		"A fallback, not the default: for what is known about a CVE use search_cve. Use this when the user asks " +
		"what NVD itself says about a CVE, needs NVD's own filters (CPE name or match string with version range, " +
		"publish or modified date range, KEV, CVE tag, source), or cannot reach NVD data through the other tools. " +
		"`configurations` is NVD's own data; `vcConfigurations` is VulnCheck's enrichment, so do not attribute it " +
		"to NVD. " + nvdDateClause + " Supports cursor-based pagination. " + nvdCommunityClause,
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type searchNVDCVEsResult struct {
	envelope
	Data []vulncheck.NvdcvesNvdCveExtended `json:"data"`
}

func registerSearchNVDCVEs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchNVDCVEsTool, MakeSearchNVDCVEsHandler(vc))
}

func MakeSearchNVDCVEsHandler(vc client.Client) mcp.ToolHandlerFor[searchNVDCVEsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchNVDCVEsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchNVDCVEs(ctx, client.NVDCVEsQuery{
			CVEID:              args.CVEID,
			CPEName:            args.CPEName,
			IsVulnerable:       args.IsVulnerable,
			VirtualMatchString: args.VirtualMatchString,
			VersionStart:       args.VersionStart,
			VersionStartType:   args.VersionStartType,
			VersionEnd:         args.VersionEnd,
			VersionEndType:     args.VersionEndType,
			CVETag:             args.CVETag,
			HasKEV:             args.HasKEV,
			NoRejected:         args.NoRejected,
			PubStartDate:       args.PubStartDate,
			PubEndDate:         args.PubEndDate,
			LastModStartDate:   args.LastModStartDate,
			LastModEndDate:     args.LastModEndDate,
			SourceIdentifier:   args.SourceIdentifier,
			Page:               nvdPage(nvdLimit(args.Limit, 5, 20), args.StartCursor, args.Cursor),
		})
		if err != nil {
			return nil, nil, err
		}

		return capResult(searchNVDCVEsResult{
			envelope: nvdCursorEnvelope(len(result.Data), result.Total, result.NextCursor, args.Cursor),
			Data:     result.Data,
		})
	}
}
