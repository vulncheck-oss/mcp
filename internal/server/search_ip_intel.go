package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

const ipIntelPrefix = "ipintel"

// defaultIPIntelLimit matches target-intel: these rows carry geolocation and ASN
// enrichment, so ten is a comfortable page and the byte bound is the real cap.
const defaultIPIntelLimit = 10

type searchIPIntelArgs struct {
	Window      string `json:"window,omitempty"       jsonschema:"Rolling window to search: '3d', '10d', '30d' or '90d' (default '3d'). Selects the ipintel index for that period"`
	CVE         string `json:"cve,omitempty"          jsonschema:"Return IPs associated with this CVE, e.g. 'CVE-2023-27350'"`
	ID          string `json:"id,omitempty"           jsonschema:"Detection type: 'c2' for command-and-control infrastructure, 'initial-access' for potentially vulnerable targets, or 'honeypot'"`
	ASN         string `json:"asn,omitempty"          jsonschema:"Autonomous System Number, e.g. 'AS16509'"`
	CIDR        string `json:"cidr,omitempty"         jsonschema:"CIDR range or single IP address, e.g. '100.20.0.0/14'"`
	Country     string `json:"country,omitempty"      jsonschema:"Country name, e.g. 'Sweden'"`
	CountryCode string `json:"country_code,omitempty" jsonschema:"ISO 3166-1 alpha-2 country code, e.g. 'US'"`
	Hostname    string `json:"hostname,omitempty"     jsonschema:"Hostname or hostname fragment, e.g. 'router.asus.com' or '.gov'"`
	ThreatActor string `json:"threat_actor,omitempty" jsonschema:"Threat actor name, e.g. 'UNC2630'"`
	Botnet      string `json:"botnet,omitempty"       jsonschema:"Botnet name, e.g. 'Fbot'"`
	Ransomware  string `json:"ransomware,omitempty"   jsonschema:"Ransomware group name, e.g. 'Cactus'"`
	MitreID     string `json:"mitre_id,omitempty"     jsonschema:"Threat actor MITRE ATT&CK group ID, e.g. 'G0013'"`
	Limit       int    `json:"limit,omitempty"        jsonschema:"Rows per page, max 200 (default 10). The response is also bounded by size and may return fewer"`
	StartCursor bool   `json:"start_cursor,omitempty" jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor      string `json:"cursor,omitempty"       jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchIPIntelTool = &mcp.Tool{
	Name:  "search_ip_intel",
	Title: "Search IP Intelligence",
	Description: "Find attacker and target IP infrastructure observed over a rolling window: command-and-control servers, honeypots, and hosts potentially targeted by initial-access exploits, with geolocation and ASN enrichment. " +
		"Filter by CVE, detection type, ASN, CIDR, country, hostname, threat actor, botnet or ransomware group. " +
		"Pick the window with the window argument rather than naming an index. " +
		"A response is a sample of the matching population and total reports its true size.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchIPIntel(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchIPIntelTool, MakeSearchIPIntelHandler(vc))
}

func MakeSearchIPIntelHandler(vc client.Client) mcp.ToolHandlerFor[searchIPIntelArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchIPIntelArgs) (*mcp.CallToolResult, any, error) {
		index, err := windowedIndex(ipIntelPrefix, args.Window)
		if err != nil {
			return nil, nil, err
		}

		result, err := vc.SearchIndex(ctx, client.SearchIndexQuery{
			Index:       index,
			CVE:         args.CVE,
			ID:          args.ID,
			ASN:         args.ASN,
			CIDR:        args.CIDR,
			Country:     args.Country,
			CountryCode: args.CountryCode,
			Hostname:    args.Hostname,
			ThreatActor: args.ThreatActor,
			Botnet:      args.Botnet,
			Ransomware:  args.Ransomware,
			MitreID:     args.MitreID,
			Limit:       productLimit(args.Limit, defaultIPIntelLimit),
			StartCursor: args.StartCursor,
			Cursor:      args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching IP intelligence: %w", err)
		}

		return capResult(newProductResponse(index, result))
	}
}
