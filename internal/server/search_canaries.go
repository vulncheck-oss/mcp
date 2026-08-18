package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

const canaryPrefix = "vulncheck-canaries"

// canaryWindowAll selects the unwindowed index, which carries the full history
// rather than a rolling period.
const canaryWindowAll = "all"

// defaultCanaryLimit is higher than the host-oriented tools because a canary event
// is a smaller record than a fingerprinted host observation.
const defaultCanaryLimit = 20

type searchCanariesArgs struct {
	Window      string `json:"window,omitempty"      jsonschema:"Rolling window to search: '3d', '10d', '30d', '90d', or 'all' for the full history (default '3d')"`
	CVE         string `json:"cve,omitempty"         jsonschema:"Return exploitation attempts against this CVE, e.g. 'CVE-2024-5276'"`
	Date        string `json:"date,omitempty"        jsonschema:"Exact date of the attack (YYYY-MM-DD), e.g. '2025-10-17'"`
	SrcCountry  string `json:"src_country,omitempty" jsonschema:"Country code the attack originated from, e.g. 'IR'"`
	DstCountry  string `json:"dst_country,omitempty" jsonschema:"Country code of the targeted canary, e.g. 'US'"`
	SrcIP       string `json:"src_ip,omitempty"      jsonschema:"Source IP address of the attack"`
	SrcASN      string `json:"src_asn,omitempty"     jsonschema:"Source ASN of the attack, e.g. 'AS12345'"`
	CIDR        string `json:"cidr,omitempty"        jsonschema:"Source CIDR range, e.g. '1.0.0.0/24'"`
	Limit       int    `json:"limit,omitempty"       jsonschema:"Rows per page, max 200 (default 20). The response is also bounded by size and may return fewer"`
	StartCursor bool   `json:"start_cursor,omitempty" jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor      string `json:"cursor,omitempty"      jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchCanariesTool = &mcp.Tool{
	Name:  "search_canaries",
	Title: "Search Canary Intelligence",
	Description: "Find exploitation attempts observed against VulnCheck's own globally deployed vulnerable canary hosts. " +
		"Because the canary is a genuinely vulnerable system, a hit is direct evidence a CVE is being attacked in the wild, not an inference — it answers \"is this being exploited right now, and by whom\". " +
		"Filter by CVE, date, source or destination country, source IP, source ASN or CIDR. " +
		"Pick the window with the window argument rather than naming an index; use 'all' for the full history. " +
		"A response is a sample of the matching events and total reports how many there are.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerSearchCanaries(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchCanariesTool, MakeSearchCanariesHandler(vc))
}

// canaryIndex resolves the window, accepting "all" for the unwindowed index.
func canaryIndex(window string) (string, error) {
	if window == canaryWindowAll {
		return canaryPrefix, nil
	}
	return windowedIndex(canaryPrefix, window)
}

func MakeSearchCanariesHandler(vc client.Client) mcp.ToolHandlerFor[searchCanariesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchCanariesArgs) (*mcp.CallToolResult, any, error) {
		index, err := canaryIndex(args.Window)
		if err != nil {
			return nil, nil, err
		}

		result, err := vc.SearchIndex(ctx, client.SearchIndexQuery{
			Index:       index,
			CVE:         args.CVE,
			Date:        args.Date,
			SrcCountry:  args.SrcCountry,
			DstCountry:  args.DstCountry,
			SrcIP:       args.SrcIP,
			SrcASN:      args.SrcASN,
			CIDR:        args.CIDR,
			Limit:       productLimit(args.Limit, defaultCanaryLimit),
			StartCursor: args.StartCursor,
			Cursor:      args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("searching canary intelligence: %w", err)
		}

		out, err := json.Marshal(newProductResponse(index, result))
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
