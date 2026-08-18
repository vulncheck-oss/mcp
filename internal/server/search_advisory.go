package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// advisoryRecord is the minimal view of an advisory record this handler needs:
// an identity to de-duplicate on, and the product names to list when a product
// filter matches nothing. Every other field is passed through to the model
// untouched, which is why the records are carried as raw JSON.
type advisoryRecord struct {
	CveMetadata struct {
		CveID string `json:"cveId"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna advisoryContainer   `json:"cna"`
		Adp []advisoryContainer `json:"adp"`
	} `json:"containers"`
}

type advisoryContainer struct {
	Affected []struct {
		Product     string `json:"product"`
		PackageName string `json:"packageName"`
	} `json:"affected"`
}

// parseAdvisoryRecord reads the two paths above. A record that will not parse
// yields the zero value rather than an error: it is still returned to the model
// verbatim, it just cannot be de-duplicated or contribute a product name.
func parseAdvisoryRecord(raw json.RawMessage) advisoryRecord {
	var record advisoryRecord
	_ = json.Unmarshal(raw, &record)
	return record
}

const (
	// maxAdvisoryLimit is the upstream maximum; above it the API returns 400.
	maxAdvisoryLimit = 100

	// defaultAdvisoryLimit is the upstream maximum, so that by default nothing is
	// withheld on row count and maxResponseBytes is the only bound.
	//
	// Any smaller default is arbitrary and unsafe. The API applies its exact
	// vendor/product filter to a page only after slicing it, so the rows that
	// survive — and therefore the order of the union — depend on the page size
	// requested. A row-count default below the size of the union silently drops
	// records at a position that shifts with the requested limit and with upstream
	// paging, which cannot be reasoned about from the outside. Callers that want a
	// smaller answer ask for one; that request is honoured exactly.
	defaultAdvisoryLimit = maxAdvisoryLimit

	// maxVendorVariants bounds the case fan-out to one call per spelling.
	maxVendorVariants = 3

	// maxListedProducts caps the product names reported when the product filter is
	// dropped, so a large vendor cannot flood the response.
	maxListedProducts = 25
)

const (
	widenedNote = "vendor matched case-sensitively upstream, so this response unions several " +
		"capitalisations; pagination is unavailable for a widened search — re-run with a single " +
		"exact vendor spelling to paginate"

	productDroppedNote = "no advisory matched that product, so the product filter was dropped and " +
		"the vendor's advisories are returned instead; product strings are CNA prose and are matched " +
		"exactly, so pick one from products_found rather than guessing"

	totalMismatchNote = "total counts documents matched before the API's exact vendor/product filter " +
		"runs, so it is an upper bound on what any spelling can return rather than a count of " +
		"withheld records"

	trimmedNote = "more records were found than the requested limit; raise limit to see the rest"

	slugNote = "vendor strings are not normalised across sources: GHSA-derived advisories use the " +
		"publisher's GitHub organisation slug, which is often the plural or hyphenated form of the " +
		"company name, and other CNAs may use an intercapped brand name. Neither is a capitalisation " +
		"of the other, so if results look thin, retry with the slug or brand spelling"

	variantFailedNote = "one or more alternative capitalisations could not be retrieved, so this " +
		"result may be missing advisories filed under them; see vendors_failed"

	truncatedNote = "advisory records vary hugely in size, so rows were dropped to keep this " +
		"response within a usable context budget; dropped rows are omitted whole, never abridged — " +
		"narrow the query or fetch a specific cve_id for the rest"
)

type searchAdvisoryArgs struct {
	Name          string `json:"name,omitempty"           jsonschema:"Advisory feed name, e.g. 'ghsa' — use v4_list_advisories to discover valid names"`
	CveID         string `json:"cve_id,omitempty"         jsonschema:"Filter by CVE ID, e.g. 'CVE-2024-1234'"`
	Vendor        string `json:"vendor,omitempty"         jsonschema:"Filter by vendor as the CNA published it. Matched exactly and case-sensitively upstream; alternative capitalisations are retried automatically"`
	Product       string `json:"product,omitempty"        jsonschema:"Filter by product as the CNA published it, which is often prose rather than a slug. Matched exactly, with no prefix or substring matching; if nothing matches, the filter is dropped and the vendor's product names are listed instead"`
	Platform      string `json:"platform,omitempty"       jsonschema:"Filter by OS or platform"`
	Version       string `json:"version,omitempty"        jsonschema:"Filter by product version (semver-aware)"`
	CPE           string `json:"cpe,omitempty"            jsonschema:"Filter by CPE 2.3 string"`
	PackageName   string `json:"package_name,omitempty"   jsonschema:"Filter by registry package name, including any scope — the most reliable filter for package-ecosystem software"`
	PURL          string `json:"purl,omitempty"           jsonschema:"Filter by Package URL (PURL)"`
	UpdatedAfter  string `json:"updated_after,omitempty"  jsonschema:"Return advisories updated after this date (RFC3339 or date-math, e.g. 'now-30d')"`
	UpdatedBefore string `json:"updated_before,omitempty" jsonschema:"Return advisories updated before this date (RFC3339 or date-math)"`
	Limit         int32  `json:"limit,omitempty"          jsonschema:"Maximum records to return, max 100 (default: 100, bounded instead by response size). Lower it only to shrink the response: because the API filters each page after slicing it, a smaller limit withholds records rather than selecting the most relevant ones"`
	StartCursor   bool   `json:"start_cursor,omitempty"   jsonschema:"Set true on the first call to enable cursor-based pagination"`
	Cursor        string `json:"cursor,omitempty"         jsonschema:"Cursor token from a previous next_cursor to fetch the next page"`
}

var SearchAdvisoryTool = &mcp.Tool{
	Name:  "v4_search_advisory",
	Title: "Search Advisory",
	Description: "Search VulnCheck v4 advisory feeds. Filter by advisory name, CVE ID, vendor, product, version, CPE, PURL, and more. " +
		"This is the tool that finds advisories carrying no CPE data, such as GHSA records for npm, PyPI and Go software — prefer it over the CPE tools for package-ecosystem products. " +
		"Vendor and product are matched exactly and case-sensitively against the CNA-published strings; alternative capitalisations are retried automatically and an unmatchable product filter is dropped, with both explained in notes.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// searchAdvisoryResponse wraps the client result so the handler can explain, in
// band, when it widened the query and why the API's own total may exceed the rows
// returned. Every added field is omitempty, so an un-widened response keeps the
// wire shape callers already depend on.
type searchAdvisoryResponse struct {
	*client.SearchAdvisoryResult
	Returned      int      `json:"returned,omitempty"`
	Dropped       int      `json:"dropped_for_size,omitempty"`
	DroppedCVEs   []string `json:"dropped_cves,omitempty"`
	VendorsTried  []string `json:"vendors_tried,omitempty"`
	VendorsFailed []string `json:"vendors_failed,omitempty"`
	ProductsFound []string `json:"products_found,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

func registerSearchAdvisory(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchAdvisoryTool, MakeSearchAdvisoryHandler(vc))
}

func MakeSearchAdvisoryHandler(vc client.Client) mcp.ToolHandlerFor[searchAdvisoryArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchAdvisoryArgs) (*mcp.CallToolResult, any, error) {
		query := advisoryQuery(args)

		result, err := vc.SearchAdvisory(ctx, query)
		if err != nil {
			return nil, nil, fmt.Errorf("searching advisories: %w", err)
		}

		response := searchAdvisoryResponse{SearchAdvisoryResult: result}
		if canWiden(query) && underDelivered(result) {
			response = widenAdvisorySearch(ctx, vc, query, result)
			// Widening reads larger upstream pages than the caller asked for,
			// because the exact filter downstream of them only sees one page. That
			// is a transport detail: `limit` still means "at most this many rows",
			// so the union is trimmed back to it.
			if int(query.Limit) < len(response.Data) {
				response.Data = response.Data[:query.Limit]
				response.Notes = append(response.Notes, trimmedNote)
			}
		}

		if dropped, ids := capAdvisoryBytes(&response); dropped > 0 {
			response.Dropped = dropped
			response.DroppedCVEs = ids
			response.Notes = append(response.Notes, truncatedNote)
		}

		response.Returned = len(response.Data)
		if int(response.Total) > len(response.Data) {
			response.Notes = append(response.Notes, totalMismatchNote, slugNote)
		}

		out, err := json.Marshal(response)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}

// capAdvisoryBytes trims the response to the shared byte budget, naming dropped
// records by CVE ID so the caller can fetch them individually afterwards.
func capAdvisoryBytes(response *searchAdvisoryResponse) (int, []string) {
	if response.SearchAdvisoryResult == nil {
		return 0, nil
	}

	bound := boundRows(rowBound{
		Envelope: response,
		Rows:     response.Data,
		Identify: func(raw json.RawMessage) string {
			return parseAdvisoryRecord(raw).CveMetadata.CveID
		},
		MaxNamed: maxListedProducts,
	})

	response.Data = bound.Kept
	return bound.Dropped, bound.Names
}

func advisoryQuery(args searchAdvisoryArgs) client.SearchAdvisoryQuery {
	limit := args.Limit
	if limit <= 0 {
		limit = defaultAdvisoryLimit
	}
	if limit > maxAdvisoryLimit {
		limit = maxAdvisoryLimit
	}

	return client.SearchAdvisoryQuery{
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
	}
}

// coveringLimit returns a page size large enough to hold every document the API
// says matches, so the exact filter downstream of it sees the whole set rather than
// an unstable sample. It never shrinks the caller's limit and never exceeds the
// upstream maximum.
func coveringLimit(limit, total int32) int32 {
	if total > limit {
		limit = total
	}
	if limit > maxAdvisoryLimit {
		limit = maxAdvisoryLimit
	}
	return limit
}

// canWiden reports whether retrying is meaningful. A cursor addresses one
// specific query's page and cannot be replayed against a different spelling, so
// paginated calls are always passed through untouched.
func canWiden(q client.SearchAdvisoryQuery) bool {
	return q.Vendor != "" && q.Cursor == ""
}

// underDelivered reports whether the API's exact post-filter appears to have
// discarded matches: either nothing survived, or it reports more matching
// documents than it handed back.
func underDelivered(r *client.SearchAdvisoryResult) bool {
	return len(r.Data) == 0 || int(r.Total) > len(r.Data)
}

// widenAdvisorySearch retries the query under alternative vendor capitalisations
// and, if that still finds nothing, once more without the product filter.
//
// Both are workarounds for the upstream filter comparing vendor and product with
// a case-sensitive `==` after the page has been sliced. They should be deleted
// once the API matches case-insensitively — at which point a single call returns
// the full set and this function has no job left.
func widenAdvisorySearch(
	ctx context.Context,
	vc client.Client,
	query client.SearchAdvisoryQuery,
	first *client.SearchAdvisoryResult,
) searchAdvisoryResponse {
	// The upstream filter runs on one page at a time, and that page's ordering is
	// not stable between calls, so while total exceeds the page size which rows
	// survive varies run to run. Widening the page to cover the whole match set
	// makes the answer both complete and reproducible; beyond the upstream maximum
	// it is capped, and the byte budget bounds the response either way.
	narrow := query.Limit
	query.Limit = coveringLimit(query.Limit, first.Total)

	merged := newAdvisoryMerge(first)
	tried := []string{query.Vendor}
	var failed []string

	// The caller's own spelling was queried at the narrower limit, so repeat it at
	// the covering one rather than keeping a partial page. Skipped when the limit
	// did not actually grow, since that would just repeat the call already made.
	if query.Limit > narrow {
		if requery, err := vc.SearchAdvisory(ctx, query); err == nil {
			merged.add(requery)
		}
	}

	for _, vendor := range vendorCaseVariants(query.Vendor) {
		if vendor == query.Vendor {
			continue
		}
		tried = append(tried, vendor)

		next := query
		next.Vendor = vendor
		// A failing variant must not discard the rows already collected; the
		// caller's own spelling already succeeded or we would not be here. It is
		// reported rather than swallowed, so a systemic upstream failure cannot
		// masquerade as "this spelling has no advisories".
		res, err := vc.SearchAdvisory(ctx, next)
		if err != nil {
			failed = append(failed, vendor)
			continue
		}
		merged.add(res)
	}

	notes := []string{widenedNote}
	if len(failed) > 0 {
		notes = append(notes, variantFailedNote)
	}

	response := searchAdvisoryResponse{
		SearchAdvisoryResult: merged.result(),
		VendorsTried:         tried,
		VendorsFailed:        failed,
		Notes:                notes,
	}
	if len(response.Data) > 0 || query.Product == "" {
		return response
	}

	// Product strings are CNA prose, often with spaces and punctuation, matched
	// exactly. A plausible guess therefore matches nothing, and returning the
	// vendor's advisories plus the real product names is more use than an empty
	// result.
	return dropProductFilter(ctx, vc, query, tried)
}

func dropProductFilter(
	ctx context.Context,
	vc client.Client,
	query client.SearchAdvisoryQuery,
	tried []string,
) searchAdvisoryResponse {
	query.Product = ""
	// Dropping the filter widens the match set by an unknown amount, and the same
	// unstable-page problem applies, so request the largest page the API allows.
	// The byte budget bounds the response.
	query.Limit = maxAdvisoryLimit

	var merged *advisoryMerge
	var failed []string
	for _, vendor := range tried {
		next := query
		next.Vendor = vendor
		res, err := vc.SearchAdvisory(ctx, next)
		if err != nil {
			failed = append(failed, vendor)
			continue
		}
		if merged == nil {
			merged = newAdvisoryMerge(res)
			continue
		}
		merged.add(res)
	}
	if merged == nil {
		merged = newAdvisoryMerge(&client.SearchAdvisoryResult{Data: []json.RawMessage{}})
	}

	result := merged.result()

	notes := []string{productDroppedNote, widenedNote}
	if len(failed) > 0 {
		notes = append(notes, variantFailedNote)
	}

	return searchAdvisoryResponse{
		SearchAdvisoryResult: result,
		VendorsTried:         tried,
		VendorsFailed:        failed,
		ProductsFound:        productNames(result.Data),
		Notes:                notes,
	}
}

// vendorCaseVariants returns the spellings to try, in a fixed order so the merged
// result is deterministic: as supplied, lowercase, then capitalised.
//
// This cannot reach every spelling. Publisher GitHub organisation slugs and
// intercapped brand names are not capitalisations of what a caller would type, so
// slugNote points the caller at those instead.
func vendorCaseVariants(vendor string) []string {
	variants := make([]string, 0, maxVendorVariants)
	for _, candidate := range []string{vendor, strings.ToLower(vendor), capitalise(vendor)} {
		if candidate == "" || slices.Contains(variants, candidate) {
			continue
		}
		variants = append(variants, candidate)
	}
	return variants
}

func capitalise(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	return string(unicode.ToUpper(runes[0])) + strings.ToLower(string(runes[1:]))
}

// advisoryMerge unions results from several vendor spellings, de-duplicating by
// CVE ID.
//
// Each spelling's rows are kept as a separate batch and interleaved on output, so
// that trimming the union to the caller's limit takes a fair share from every
// spelling. Concatenating instead would put the later spellings last and let a
// small limit discard precisely the rows the fan-out went looking for.
type advisoryMerge struct {
	batches [][]json.RawMessage
	seen    map[string]struct{}
	total   int32
}

func newAdvisoryMerge(first *client.SearchAdvisoryResult) *advisoryMerge {
	m := &advisoryMerge{seen: map[string]struct{}{}}
	m.add(first)
	return m
}

func (m *advisoryMerge) add(r *client.SearchAdvisoryResult) {
	// Every spelling reports the same pre-filter count for the same coarse match,
	// so summing would multiply it. Keep the largest seen.
	if r.Total > m.total {
		m.total = r.Total
	}
	batch := make([]json.RawMessage, 0, len(r.Data))
	for _, raw := range r.Data {
		// Records without a CVE ID cannot be de-duplicated; keep them rather than
		// collapsing distinct advisories into one.
		record := parseAdvisoryRecord(raw)
		if id := record.CveMetadata.CveID; id != "" {
			if _, ok := m.seen[id]; ok {
				continue
			}
			m.seen[id] = struct{}{}
		}
		batch = append(batch, raw)
	}
	if len(batch) > 0 {
		m.batches = append(m.batches, batch)
	}
}

// result reports the union, interleaved across spellings. NextCursor is
// deliberately dropped: it belongs to one spelling's query and cannot paginate a
// union.
func (m *advisoryMerge) result() *client.SearchAdvisoryResult {
	var size int
	for _, batch := range m.batches {
		size += len(batch)
	}

	data := make([]json.RawMessage, 0, size)
	for i := 0; len(data) < size; i++ {
		for _, batch := range m.batches {
			if i < len(batch) {
				data = append(data, batch[i])
			}
		}
	}

	return &client.SearchAdvisoryResult{Data: data, Total: m.total}
}

// productNames lists the distinct product and package names present, so a caller
// whose product guess missed can pick a real one.
func productNames(data []json.RawMessage) []string {
	seen := map[string]struct{}{}
	names := make([]string, 0, maxListedProducts)

	for _, raw := range data {
		record := parseAdvisoryRecord(raw)
		affected := record.Containers.Cna.Affected
		for _, adp := range record.Containers.Adp {
			affected = append(affected, adp.Affected...)
		}
		for _, a := range affected {
			for _, name := range []string{a.Product, a.PackageName} {
				if name == "" || len(names) == maxListedProducts {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return names
}
