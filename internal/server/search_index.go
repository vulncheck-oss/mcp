package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchIndexArgs struct {
	Index              string `json:"index"                           jsonschema:"Index name to search, e.g. 'vulncheck-nvd2', 'initial-access', 'vulncheck-kev'"`
	CVE                string `json:"cve,omitempty"                   jsonschema:"Filter by CVE ID, e.g. 'CVE-2021-44228'"`
	Alias              string `json:"alias,omitempty"                 jsonschema:"Filter by vulnerability alias, e.g. 'GHSA-xxxx-xxxx-xxxx'"`
	IAVA               string `json:"iava,omitempty"                  jsonschema:"Filter by IAVA identifier"`
	LastModStartDate   string `json:"last_mod_start_date,omitempty"   jsonschema:"Filter by last-modified date range start (YYYY-MM-DD)"`
	LastModEndDate     string `json:"last_mod_end_date,omitempty"     jsonschema:"Filter by last-modified date range end (YYYY-MM-DD)"`
	PubStartDate       string `json:"pub_start_date,omitempty"        jsonschema:"Filter by publication date range start (YYYY-MM-DD)"`
	PubEndDate         string `json:"pub_end_date,omitempty"          jsonschema:"Filter by publication date range end (YYYY-MM-DD)"`
	UpdatedAtStartDate string `json:"updated_at_start_date,omitempty" jsonschema:"Filter by data source update date range start (YYYY-MM-DD)"`
	UpdatedAtEndDate   string `json:"updated_at_end_date,omitempty"   jsonschema:"Filter by data source update date range end (YYYY-MM-DD)"`
	Date               string `json:"date,omitempty"                  jsonschema:"Filter by exact date (YYYY-MM-DD) — equivalent to setting both start and end to the same date"`
	ThreatActor        string `json:"threat_actor,omitempty"          jsonschema:"Filter by threat actor name, e.g. 'UNC2630'. Valid on the threat-actors, botnets, ransomware, exploits and vulnerability indices"`
	MitreID            string `json:"mitre_id,omitempty"              jsonschema:"Filter by a threat actor's MITRE ATT&CK group ID, e.g. 'G0013'"`
	MispID             string `json:"misp_id,omitempty"               jsonschema:"Filter by a threat actor's MISP ID"`
	Ransomware         string `json:"ransomware,omitempty"            jsonschema:"Filter by ransomware group name, e.g. 'Cactus'"`
	Botnet             string `json:"botnet,omitempty"                jsonschema:"Filter by botnet name, e.g. 'Fbot'"`
	JVNDB              string `json:"jvndb,omitempty"                 jsonschema:"Filter by Japanese vulnerability database ID, e.g. 'JVNDB-2025-007355'"`
	Sort               string `json:"sort,omitempty"                  jsonschema:"Sort results by '_timestamp' or 'date_added'"`
	Order              string `json:"order,omitempty"                 jsonschema:"Sort direction: 'asc' or 'desc'"`
	Limit              int    `json:"limit,omitempty"                 jsonschema:"Number of results per page (default 1)"`
	StartCursor        bool   `json:"start_cursor,omitempty"          jsonschema:"Set true on the first call to enable cursor-based pagination; subsequent calls use the returned next_cursor value instead"`
	Cursor             string `json:"cursor,omitempty"                jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchIndexTool = &mcp.Tool{
	Name:  "search_index",
	Title: "Search Index",
	Description: "Query a VulnCheck index by name (required). Use list_indices to discover available index names. " +
		"Filter by CVE, alias, IAVA, JVNDB ID, threat actor, MITRE ATT&CK group, MISP ID, ransomware group, botnet, and date ranges. Supports sorting and cursor-based pagination. " +
		"For IP Intelligence, Target Intelligence and Canary Intelligence use search_ip_intel, search_target_intel and search_canaries instead — they expose host and network filters this tool does not.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type searchIndexResult struct {
	Data       []json.RawMessage `json:"data"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Total      int               `json:"total"`
}

func registerSearchIndex(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchIndexTool, MakeSearchIndexHandler(vc))
}

func MakeSearchIndexHandler(vc client.Client) mcp.ToolHandlerFor[searchIndexArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchIndexArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 1
		}

		result, err := vc.SearchIndex(ctx, client.SearchIndexQuery{
			Index:              args.Index,
			CVE:                args.CVE,
			Cursor:             args.Cursor,
			Limit:              limit,
			StartCursor:        args.StartCursor,
			LastModStartDate:   args.LastModStartDate,
			LastModEndDate:     args.LastModEndDate,
			PubStartDate:       args.PubStartDate,
			PubEndDate:         args.PubEndDate,
			UpdatedAtStartDate: args.UpdatedAtStartDate,
			UpdatedAtEndDate:   args.UpdatedAtEndDate,
			Date:               args.Date,
			Alias:              args.Alias,
			IAVA:               args.IAVA,
			ThreatActor:        args.ThreatActor,
			MitreID:            args.MitreID,
			MispID:             args.MispID,
			Ransomware:         args.Ransomware,
			Botnet:             args.Botnet,
			JVNDB:              args.JVNDB,
			Sort:               args.Sort,
			Order:              args.Order,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching index: %w", err)
		}

		out, err := json.Marshal(searchIndexResult{
			Data:       result.Data,
			NextCursor: result.NextCursor,
			Total:      result.Total,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
