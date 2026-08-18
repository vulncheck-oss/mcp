package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

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

	// The advice deliberately does not suggest changing the window. Whichever feed is
	// part-way through a bulk update fills the page, and which feed that is depends on
	// when the call is made, so a narrower or wider window lands on a different
	// dominating feed rather than a mixed one. Scoping by feed is the only reliable
	// escape.
	digestConcentrationNote = "one feed accounts for nearly all of this page, which means that feed is " +
		"part-way through a bulk update rather than that little else changed. Changing the window " +
		"will not help — it lands on whichever feed is updating then. Pass name to scope to a feed"

	digestNoProseNote = "most of these rows carry identity and timing only, because the feed filling " +
		"this page publishes scores or metadata rather than advisory prose. Pass name to scope to a " +
		"feed that publishes titles and descriptions"
)

type listRecentAdvisoriesArgs struct {
	UpdatedAfter  string `json:"updated_after,omitempty"  jsonschema:"Return advisories updated after this point. RFC3339, or relative like 'now-24h' or 'now-7d'. Defaults to 'now-24h'. Same field as v4_search_advisory's updated_after"`
	UpdatedBefore string `json:"updated_before,omitempty" jsonschema:"Return advisories updated before this point. RFC3339 or relative. Same field as v4_search_advisory's updated_before"`
	Name          string `json:"name,omitempty"         jsonschema:"Restrict to a single advisory feed, e.g. 'ghsa'. Use v4_list_advisories to discover names. Without it, a feed undergoing a bulk update can dominate the results"`
	Vendor        string `json:"vendor,omitempty"       jsonschema:"Filter by vendor as the CNA published it, matched exactly and case-sensitively"`
	Product       string `json:"product,omitempty"      jsonschema:"Filter by product as the CNA published it, matched exactly"`
	Limit         int32  `json:"limit,omitempty"        jsonschema:"Rows per page, max 100 (default 25)"`
	StartCursor   bool   `json:"start_cursor,omitempty" jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor        string `json:"cursor,omitempty"       jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
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
		// sentence, which is what a title would have summarised.
		title = firstSentence(strings.TrimSpace(cna.Descriptions[0].Value))
	}
	title = truncateRunes(title, maxDigestTitle)

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

// firstSentence returns the leading sentence of a description.
//
// A full stop only ends a sentence when it is followed by whitespace and a capital
// letter. Advisory descriptions are dense with version numbers, and cutting at the
// first full stop turns "versions prior to 12.1.4" into "versions prior to 12" — an
// abbreviated title that reads as a different, wrong statement rather than a truncated
// one. Requiring whitespace and a capital also steps over "e.g." and "Inc." for free.
func firstSentence(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}

	for i, r := range s {
		if i == 0 || (r != '.' && r != '!' && r != '?') {
			continue
		}
		tail := s[i+1:]
		rest := strings.TrimLeftFunc(tail, unicode.IsSpace)
		if rest == "" {
			// Trailing terminator: the whole string is one sentence.
			return s[:i]
		}
		if len(rest) == len(tail) {
			// No whitespace followed, so this is inside a number or an identifier.
			continue
		}
		if next, _ := utf8.DecodeRuneInString(rest); unicode.IsUpper(next) {
			return s[:i]
		}
	}
	return s
}

// truncateRunes shortens a string to at most limit runes.
//
// Slicing by byte can split a multi-byte rune and emit invalid UTF-8, which is
// reachable here because advisory descriptions routinely carry non-ASCII text.
func truncateRunes(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return strings.TrimSpace(string(runes[:limit])) + "…"
}

func registerListRecentAdvisories(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListRecentAdvisoriesTool, MakeListRecentAdvisoriesHandler(vc))
}

func MakeListRecentAdvisoriesHandler(vc client.Client) mcp.ToolHandlerFor[listRecentAdvisoriesArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args listRecentAdvisoriesArgs) (*mcp.CallToolResult, any, error) {
		updatedAfter := args.UpdatedAfter
		if updatedAfter == "" {
			updatedAfter = defaultRecentWindow
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
			UpdatedAfter:  updatedAfter,
			UpdatedBefore: args.UpdatedBefore,
			Limit:         limit,
			StartCursor:   args.StartCursor,
			Cursor:        args.Cursor,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("listing recent advisories: %w", err)
		}

		response := buildRecentAdvisories(result, digestQuery{
			UpdatedAfter:  updatedAfter,
			UpdatedBefore: args.UpdatedBefore,
			Name:          args.Name,
		})

		out, err := json.Marshal(response)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}

// digestQuery carries the request fields the response needs to describe itself,
// rather than passing several interchangeable strings positionally.
type digestQuery struct {
	UpdatedAfter  string
	UpdatedBefore string
	Name          string
}

func buildRecentAdvisories(result *client.SearchAdvisoryResult, q digestQuery) recentAdvisoriesResponse {
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
		Window:     describeWindow(q.UpdatedAfter, q.UpdatedBefore),
		Providers:  topProviders(providers),
		NextCursor: result.NextCursor,
		Notes:      []string{digestNote},
	}

	if int(result.Total) > len(rows) {
		response.Notes = append(response.Notes, digestPartialNote)
	}
	// A single feed dominating usually means it is mid-bulk-update, which makes the
	// page look like the whole story when it is one source's churn.
	if q.Name == "" && dominatedBySingleProvider(providers) {
		response.Notes = append(response.Notes, digestConcentrationNote)
	}
	// Some feeds publish scores or metadata with no prose at all, so a page they fill
	// projects to identity and timing and nothing else. Saying so is the difference
	// between a caller thinking the data is thin and knowing to scope by feed.
	if q.Name == "" && mostRowsLackProse(rows) {
		response.Notes = append(response.Notes, digestNoProseNote)
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
		// Returned as-is rather than copied. The caller built this map for this
		// response and does not read it again afterwards, so sharing it is safe.
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

// dominatedBySingleProvider compares the largest feed against the rows that were
// actually attributed to a feed, not against every row. Counting unattributed rows in
// the denominator would raise the bar and hide domination that is really there.
func dominatedBySingleProvider(counts map[string]int) bool {
	attributed, highest := 0, 0
	for _, c := range counts {
		attributed += c
		if c > highest {
			highest = c
		}
	}
	if attributed < 10 {
		return false
	}
	return highest*10 >= attributed*9
}

// mostRowsLackProse reports whether the page is largely rows with neither a title nor
// a usable description, which is what a score-only feed projects to.
func mostRowsLackProse(rows []advisoryDigestRow) bool {
	if len(rows) < 10 {
		return false
	}
	bare := 0
	for _, r := range rows {
		if r.Title == "" {
			bare++
		}
	}
	return bare*10 >= len(rows)*9
}
