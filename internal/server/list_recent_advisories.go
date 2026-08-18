package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

const (
	// defaultRecentWindow keeps the common question — what changed since yesterday —
	// answerable with no arguments at all.
	defaultRecentWindow = "now-24h"

	// defaultRecentLimit is deliberately modest. Each projected row is tiny, but the
	// server has to receive the whole record to project it, and advisory records vary
	// by two orders of magnitude between feeds. A larger page costs upstream transfer
	// rather than caller context, so callers who want more ask for it.
	defaultRecentLimit = 25

	// maxRecentLimit is the upstream maximum for this endpoint.
	maxRecentLimit = 100

	// maxDigestSummaryEntries caps the provider breakdown so a diverse page cannot
	// crowd out the rows it is describing.
	maxDigestSummaryEntries = 15
)

const (
	digestNote = "this is a digest: each row carries identity, provenance and timing only, not the " +
		"full advisory record. Use v4_search_advisory with a cve_id for the complete record"

	digestPartialNote = "total counts every advisory matching this window; these rows are the current " +
		"page of it, not the whole set"

	digestConcentrationNote = "one feed accounts for nearly all of this page, which usually means that " +
		"feed is mid-bulk-update rather than that little else changed — pass name to look at a " +
		"specific feed, or narrow the window"
)

type listRecentAdvisoriesArgs struct {
	Since       string `json:"since,omitempty"        jsonschema:"Return advisories updated after this point. RFC3339, or relative like 'now-24h' or 'now-7d'. Defaults to 'now-24h'"`
	Until       string `json:"until,omitempty"        jsonschema:"Return advisories updated before this point. RFC3339 or relative"`
	Name        string `json:"name,omitempty"         jsonschema:"Restrict to a single advisory feed, e.g. 'ghsa'. Use v4_list_advisories to discover names. Without it, a feed undergoing a bulk update can dominate the results"`
	Vendor      string `json:"vendor,omitempty"       jsonschema:"Filter by vendor as the CNA published it, matched exactly and case-sensitively"`
	Product     string `json:"product,omitempty"      jsonschema:"Filter by product as the CNA published it, matched exactly"`
	Limit       int32  `json:"limit,omitempty"        jsonschema:"Rows per page, max 100 (default 25)"`
	StartCursor bool   `json:"start_cursor,omitempty" jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor      string `json:"cursor,omitempty"       jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var ListRecentAdvisoriesTool = &mcp.Tool{
	Name:  "list_recent_advisories",
	Title: "List Recent Advisories",
	Description: "Summarise which advisories were published or updated over a time window — the answer to \"what changed recently\". " +
		"Returns a compact digest of identity, provenance and timing rather than full advisory records, so a page of results costs a fraction of the underlying data. " +
		"Defaults to the last 24 hours. Optionally restrict to one feed, or filter by vendor or product. " +
		"Follow up with v4_search_advisory and a cve_id for any record in full.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// advisoryDigestRow is the projected view of an advisory: enough to decide whether a
// record is worth fetching in full, and nothing else.
type advisoryDigestRow struct {
	CVE       string `json:"cve,omitempty"`
	Title     string `json:"title,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Published string `json:"published,omitempty"`
	Updated   string `json:"updated,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type recentAdvisoriesResponse struct {
	Data       []advisoryDigestRow `json:"data"`
	Returned   int                 `json:"returned"`
	Total      int32               `json:"total"`
	Window     string              `json:"window"`
	Providers  map[string]int      `json:"providers,omitempty"`
	NextCursor string              `json:"next_cursor,omitempty"`
	Notes      []string            `json:"notes,omitempty"`
}

// advisoryDigestSource is the subset of a CVE 5.x record the digest reads. Titles and
// descriptions are absent from some feeds, so both are consulted and either may be
// missing without that being an error.
type advisoryDigestSource struct {
	CveMetadata struct {
		CveID         string `json:"cveId"`
		DatePublished string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			Title            string `json:"title"`
			ProviderMetadata struct {
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
			Descriptions []struct {
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
	} `json:"containers"`
}

// maxDigestTitle bounds a description used as a title fallback, so one verbose entry
// cannot dominate the digest.
const maxDigestTitle = 160

func projectAdvisory(raw json.RawMessage) advisoryDigestRow {
	var src advisoryDigestSource
	// A record that will not parse still yields a row: an empty projection is more
	// honest than dropping it and understating the count.
	_ = json.Unmarshal(raw, &src)

	cna := src.Containers.Cna
	title := strings.TrimSpace(cna.Title)
	if title == "" && len(cna.Descriptions) > 0 {
		// Several feeds carry no title at all, so fall back to the description's first
		// line, which is what a title would have summarised.
		title = strings.TrimSpace(cna.Descriptions[0].Value)
		if i := strings.IndexAny(title, ".\n"); i > 0 {
			title = title[:i]
		}
	}
	if len(title) > maxDigestTitle {
		title = strings.TrimSpace(title[:maxDigestTitle]) + "…"
	}

	var ref string
	if len(cna.References) > 0 {
		ref = cna.References[0].URL
	}

	return advisoryDigestRow{
		CVE:       src.CveMetadata.CveID,
		Title:     title,
		Provider:  cna.ProviderMetadata.ShortName,
		Published: src.CveMetadata.DatePublished,
		Updated:   cna.ProviderMetadata.DateUpdated,
		Reference: ref,
	}
}

func registerListRecentAdvisories(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListRecentAdvisoriesTool, MakeListRecentAdvisoriesHandler(vc))
}

func MakeListRecentAdvisoriesHandler(vc client.Client) mcp.ToolHandlerFor[listRecentAdvisoriesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args listRecentAdvisoriesArgs) (*mcp.CallToolResult, any, error) {
		since := args.Since
		if since == "" {
			since = defaultRecentWindow
		}
		limit := args.Limit
		if limit <= 0 {
			limit = defaultRecentLimit
		}
		if limit > maxRecentLimit {
			limit = maxRecentLimit
		}

		result, err := vc.SearchAdvisory(ctx, client.SearchAdvisoryQuery{
			Name:          args.Name,
			Vendor:        args.Vendor,
			Product:       args.Product,
			UpdatedAfter:  since,
			UpdatedBefore: args.Until,
			Limit:         limit,
			StartCursor:   args.StartCursor,
			Cursor:        args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("listing recent advisories: %w", err)
		}

		response := buildRecentAdvisories(result, since, args.Until, args.Name)

		out, err := json.Marshal(response)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}

func buildRecentAdvisories(result *client.SearchAdvisoryResult, since, until, name string) recentAdvisoriesResponse {
	rows := make([]advisoryDigestRow, 0, len(result.Data))
	providers := map[string]int{}
	for _, raw := range result.Data {
		row := projectAdvisory(raw)
		rows = append(rows, row)
		if row.Provider != "" {
			providers[row.Provider]++
		}
	}

	response := recentAdvisoriesResponse{
		Data:       rows,
		Returned:   len(rows),
		Total:      result.Total,
		Window:     describeWindow(since, until),
		Providers:  topProviders(providers),
		NextCursor: result.NextCursor,
		Notes:      []string{digestNote},
	}

	if int(result.Total) > len(rows) {
		response.Notes = append(response.Notes, digestPartialNote)
	}
	// A single feed dominating usually means it is mid-bulk-update, which makes the
	// page look like the whole story when it is one source's churn.
	if name == "" && dominatedBySingleProvider(providers, len(rows)) {
		response.Notes = append(response.Notes, digestConcentrationNote)
	}

	return response
}

func describeWindow(since, until string) string {
	if until == "" {
		return "updated after " + since
	}
	return "updated between " + since + " and " + until
}

// topProviders keeps the breakdown bounded, preferring the largest counts and
// breaking ties by name so the output is stable.
func topProviders(counts map[string]int) map[string]int {
	if len(counts) <= maxDigestSummaryEntries {
		return counts
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	top := make(map[string]int, maxDigestSummaryEntries)
	for _, n := range names[:maxDigestSummaryEntries] {
		top[n] = counts[n]
	}
	return top
}

func dominatedBySingleProvider(counts map[string]int, rows int) bool {
	if rows < 10 || len(counts) == 0 {
		return false
	}
	highest := 0
	for _, c := range counts {
		if c > highest {
			highest = c
		}
	}
	return highest*10 >= rows*9
}
