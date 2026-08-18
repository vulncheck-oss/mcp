package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// targetIntelIndex is a single index with no rolling window, unlike the ipintel and
// canary families.
const targetIntelIndex = "target-intel"

// defaultTargetIntelLimit is 10 because these records are large: each carries
// per-fingerprint detail plus network enrichment. The byte bound is the real cap;
// this keeps the common case comfortable.
const defaultTargetIntelLimit = 10

type searchTargetIntelArgs struct {
	CVE             string `json:"cve,omitempty"             jsonschema:"Return hosts confirmed vulnerable to this CVE, e.g. 'CVE-2024-21887'"`
	CIDR            string `json:"cidr,omitempty"           jsonschema:"CIDR range, or a single host with /32, e.g. '203.0.113.42/32'"`
	Hostname        string `json:"hostname,omitempty"       jsonschema:"Hostname resolved at scan time, e.g. 'vpn.example.com'"`
	Domain          string `json:"domain,omitempty"         jsonschema:"Domain associated with the host"`
	Vendor          string `json:"vendor,omitempty"         jsonschema:"Software vendor from fingerprinting, e.g. 'ivanti'. Combine with product for a targeted result; vendor alone is broad"`
	Product         string `json:"product,omitempty"        jsonschema:"Software product from fingerprinting, e.g. 'connect secure'"`
	Version         string `json:"version,omitempty"        jsonschema:"Software version string, e.g. '22.7.2.5367'"`
	CPE             string `json:"cpe,omitempty"            jsonschema:"Full CPE 2.3 string to match against fingerprinted software"`
	ASN             string `json:"asn,omitempty"            jsonschema:"Autonomous System Number, e.g. 'AS15169'"`
	Country         string `json:"country,omitempty"        jsonschema:"Country name, e.g. 'United States'"`
	CountryCode     string `json:"country_code,omitempty"   jsonschema:"ISO 3166-1 alpha-2 country code, e.g. 'US'"`
	Protocol        string `json:"protocol,omitempty"       jsonschema:"Application or service protocol observed on the port, e.g. 'http', 'telnet', 'ssh'. This is the service-level protocol, not the transport — use transport for that"`
	Transport       string `json:"transport,omitempty"      jsonschema:"Transport protocol, e.g. 'tcp'"`
	Port            int    `json:"port,omitempty"           jsonschema:"Port the service was observed on, e.g. 443"`
	Classifications string `json:"classifications,omitempty" jsonschema:"Classification tag to filter by: 'c2', 'scanner', 'proxy', 'attack-infrastructure', 'honeypot', 'mcp', 'cdn', 'sector' or 'canary-attacker'. A type:product form is also accepted, e.g. 'c2:cobalt-strike'"`
	ContainsCVE     *bool  `json:"contains_cve,omitempty"   jsonschema:"When true, return only hosts whose fingerprinted service has an associated CVE; when false, only those without"`
	Limit           int    `json:"limit,omitempty"          jsonschema:"Rows per page, max 200 (default 10). Records are large, so the response is also bounded by size and may return fewer"`
	StartCursor     bool   `json:"start_cursor,omitempty"   jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor          string `json:"cursor,omitempty"         jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchTargetIntelTool = &mcp.Tool{
	Name:  "search_target_intel",
	Title: "Search Target Intelligence",
	Description: "Find internet-facing hosts confirmed to be running vulnerable software, mapped to CVEs by version-level fingerprinting. " +
		"Answers \"which hosts are exposed to this CVE right now\", and locates infrastructure by classification — C2, scanners, proxies, honeypots. " +
		"Filter by CVE, CPE, vendor, product, version, ASN, CIDR, country, port or classification. " +
		"This index is far larger than any single response, so a result is a sample of the matching population and total reports its true size.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchTargetIntel(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchTargetIntelTool, MakeSearchTargetIntelHandler(vc))
}

func MakeSearchTargetIntelHandler(vc client.Client) mcp.ToolHandlerFor[searchTargetIntelArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchTargetIntelArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchIndex(ctx, client.SearchIndexQuery{
			Index:           targetIntelIndex,
			CVE:             args.CVE,
			CIDR:            args.CIDR,
			Hostname:        args.Hostname,
			Domain:          args.Domain,
			Vendor:          args.Vendor,
			Product:         args.Product,
			Version:         args.Version,
			CPE:             args.CPE,
			ASN:             args.ASN,
			Country:         args.Country,
			CountryCode:     args.CountryCode,
			Protocol:        args.Protocol,
			Transport:       args.Transport,
			Port:            args.Port,
			Classifications: args.Classifications,
			ContainsCVE:     args.ContainsCVE,
			Limit:           productLimit(args.Limit, defaultTargetIntelLimit),
			StartCursor:     args.StartCursor,
			Cursor:          args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching target intelligence: %w", err)
		}

		out, err := json.Marshal(newProductResponse(targetIntelIndex, result))
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
