package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchAdvisoryArgs struct {
	Name          string `json:"name,omitempty"           jsonschema:"Advisory feed name, e.g. 'ghsa' — use v4_list_advisories to discover valid names"`
	CveID         string `json:"cve_id,omitempty"         jsonschema:"Filter by CVE ID, e.g. 'CVE-2024-1234'"`
	Vendor        string `json:"vendor,omitempty"         jsonschema:"Filter by vendor name"`
	Product       string `json:"product,omitempty"        jsonschema:"Filter by product name"`
	Platform      string `json:"platform,omitempty"       jsonschema:"Filter by OS or platform"`
	Version       string `json:"version,omitempty"        jsonschema:"Filter by product version (semver-aware)"`
	CPE           string `json:"cpe,omitempty"            jsonschema:"Filter by CPE 2.3 string"`
	PackageName   string `json:"package_name,omitempty"   jsonschema:"Filter by package name"`
	PURL          string `json:"purl,omitempty"           jsonschema:"Filter by Package URL (PURL)"`
	UpdatedAfter  string `json:"updated_after,omitempty"  jsonschema:"Return advisories updated after this date (RFC3339 or date-math, e.g. 'now-30d')"`
	UpdatedBefore string `json:"updated_before,omitempty" jsonschema:"Return advisories updated before this date (RFC3339 or date-math)"`
	Limit         int32  `json:"limit,omitempty"          jsonschema:"Results per page, max 100 (default: 1)"`
	StartCursor   bool   `json:"start_cursor,omitempty"   jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor        string `json:"cursor,omitempty"         jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchAdvisoryTool = &mcp.Tool{
	Name:        "v4_search_advisory",
	Title:       "Search Advisory",
	Description: "Search VulnCheck v4 advisory feeds. Filter by advisory name, CVE ID, vendor, product, version, CPE, PURL, and more. Supports cursor-based pagination.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchAdvisory(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchAdvisoryTool, MakeSearchAdvisoryHandler(vc))
}

func MakeSearchAdvisoryHandler(vc client.Client) mcp.ToolHandlerFor[searchAdvisoryArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchAdvisoryArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 1
		}
		result, err := vc.SearchAdvisory(ctx, client.SearchAdvisoryQuery{
			Name:          args.Name,
			CveID:         args.CveID,
			Vendor:        args.Vendor,
			Product:       args.Product,
			Platform:      args.Platform,
			Version:       args.Version,
			CPE:           args.CPE,
			PackageName:   args.PackageName,
			PURL:          args.PURL,
			UpdatedAfter:  args.UpdatedAfter,
			UpdatedBefore: args.UpdatedBefore,
			Limit:         limit,
			StartCursor:   args.StartCursor,
			Cursor:        args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching advisories: %w", err)
		}

		out, err := json.Marshal(result)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
