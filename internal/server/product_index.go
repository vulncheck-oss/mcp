package server

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vulncheck-oss/mcp/internal/client"
)

// The IP Intelligence and Canary Intelligence indices are published as rolling
// windows. Callers pick a window rather than an index name, so nobody has to know
// that "ipintel-30d" is spelled that way.
var indexWindows = []string{"3d", "10d", "30d", "90d"}

const defaultWindow = "3d"

// offsetCeiling is the upstream limit on page x limit for /v3/index. Beyond it the
// API directs callers to the cursor or to a backup instead, so a result set larger
// than this cannot be reached in full by paging.
const offsetCeiling = 10_000

// maxProductLimit is the largest page size the API documents.
const maxProductLimit = 200

const (
	// populationNote adds what is true only of the host- and event-oriented indices,
	// where a page is a sample of a population rather than a slice of an enumeration.
	//
	// It stops at "sample" because partialSetNote, which always accompanies it, already
	// says the rows are partial and that total is the number to report. "Sample" is the
	// part that is not redundant: a page implies an enumeration you could walk to the
	// end, and these indices do not have one.
	populationNote = "this index describes a population of hosts or events rather than one record " +
		"per CVE, so these rows are a sample of it"

	// ceilingNote names both routes and not the mechanism.
	//
	// Both, because only one of them is obvious and it is the expensive one: sending a
	// caller to fetch a whole backup when the tool in its hand can walk the set by cursor
	// is a needlessly large answer to a small problem. The upstream error names both for
	// the same reason.
	//
	// Not the mechanism, because upstream the cap is on page x limit and no tool here
	// sends a page — a caller cannot reach that error from this server, and explaining it
	// only invites them to look for a parameter that does not exist.
	ceilingNote = "total exceeds what a single sequence of pages can reach (10000 records " +
		"upstream). Cursor pagination is not subject to that limit: pass start_cursor on the " +
		"first call, then next_cursor as cursor. For the whole set at once, use a backup of " +
		"this index"

	// droppedFilterNote names filters the index does not accept.
	//
	// It leads with the consequence, not the mechanism. The API ignores an unsupported
	// parameter and answers HTTP 200 with an unfiltered result and a total that looks
	// entirely plausible, so this note is the only thing standing between a caller and
	// reporting an unnarrowed set as a filtered one — which, on a security question, is
	// how "these hosts are linked to this actor" gets said about every host.
	droppedFilterNote = "FILTERS NOT APPLIED: this index does not accept %s. The API ignores an " +
		"unsupported filter rather than rejecting it, so these rows and total are NOT narrowed by " +
		"it and must not be reported as though they were. Call describe_index for the filters this " +
		"index accepts"

	// cursorExhaustedNote covers the other reason a page comes back empty. emptyPageNote
	// tells the caller to retry with a larger limit, which is sound advice for a page the
	// filter emptied and useless advice at the end of a cursor walk — there is nothing
	// left to page to, at any limit.
	cursorExhaustedNote = "the cursor walk is complete: this page is empty and there is no next " +
		"cursor, so every record reachable this way has already been returned. total counts what " +
		"matched upstream, not what remains — a larger limit will not produce more"

	// emptyPageNote comes in two endings because the diagnosis is shared and the remedy is
	// not. The cause is the same either way — the API filters a page after slicing it — but
	// telling a caller mid-walk to enlarge its limit is wrong, not merely unhelpful: the
	// route onward is the cursor already sitting in the response it is reading.
	emptyPageDiagnosis = "records match this query but none was returned on this page: the API " +
		"applies the filter to a page after slicing it, so a small limit can yield nothing while " +
		"total is non-zero. This is not an absence of data — "

	emptyPageNote = emptyPageDiagnosis + "retry with a larger limit"

	emptyPageMidWalkNote = emptyPageDiagnosis + "this response carries a next_cursor, so pass it " +
		"back as cursor to continue the walk"
)

// populationIndexPrefixes are the indices whose rows are hosts or events rather than one
// record per CVE.
//
// It is not dedicatedTools, which is the near-identical set plus `exploits`. That index is
// one row per CVE carrying its exploit entries — see defaultCuratedExploitsLimit — so
// calling it a population of hosts or events would be false, and it was being told exactly
// that before this set existed.
//
// It is also a deliberate under-approximation of the whole catalogue: the API publishes 506
// indices and several outside this list are many-rows-per-CVE. A miss costs one absent
// clause rather than a wrong one, because partialSetNote still goes out and still says to
// report total. A small certain set beats an exhaustive guess.
var populationIndexPrefixes = []string{targetIntelIndex, ipIntelPrefix, canaryPrefix}

// isPopulationIndex reports whether an index describes a population of hosts or events.
// Prefixes rather than exact names, because the windowed families resolve to
// "ipintel-3d", "vulncheck-canaries-all" and so on.
func isPopulationIndex(index string) bool {
	for _, prefix := range populationIndexPrefixes {
		if strings.HasPrefix(index, prefix) {
			return true
		}
	}
	return false
}

// droppedFilterNoteFor names the filters this query sent that the index does not accept, or
// returns "" when none were dropped.
//
// The comparison is free: /v3/index returns the index's own parameter list inline with every
// query, and the client records which filters it actually put on the request, so neither
// side needs a second call or a hardcoded table.
//
// Nothing is claimed when the index published no list, which happens on a zero-row response
// from some indices. That exemption is safe rather than merely convenient: a dropped filter
// is monotonic — an ignored filter is not applied, so the result can only be the same size
// or wider — so a response with no rows cannot be concealing a narrower answer than the
// caller already sees. A filter the index lists but does not honour is invisible from here;
// that one closes upstream, by rejecting unknown parameters instead of ignoring them.
func droppedFilterNoteFor(result *client.IndexQueryResult) string {
	// An empty list means the index did not publish one, which is not the same as
	// accepting nothing. The client drops blank names when parsing, so this is the only
	// check needed.
	if len(result.FiltersAccepted) == 0 {
		return ""
	}

	var dropped []string
	for _, sent := range result.FiltersSent {
		if !slices.Contains(result.FiltersAccepted, sent) {
			dropped = append(dropped, sent)
		}
	}
	if len(dropped) == 0 {
		return ""
	}

	return fmt.Sprintf(droppedFilterNote, strings.Join(dropped, ", "))
}

// indexNotes reports what the /v3/index endpoint did to a query.
//
// It is shared by the product tools and search_index because they call the same endpoint
// through the same client function and receive the same envelope. search_index carried none
// of these notes until now, despite being the tool most exposed to the empty-page trap: its
// limit defaults to 1, which is where a filter applied after slicing is most likely to
// yield nothing from a non-zero total.
func indexNotes(index string, result *client.IndexQueryResult) []string {
	returned, total := len(result.Data), result.Total

	var notes []string

	// First, because it is the only one that says the answer is wrong rather than
	// incomplete: everything below describes a partial result, this describes a result
	// that does not mean what it appears to.
	if dropped := droppedFilterNoteFor(result); dropped != "" {
		notes = append(notes, dropped)
	}

	// An empty page with a non-zero total is not an absence of data, and must not be
	// reported as a sample: the filter is applied to a page after it is sliced, so a
	// small limit can legitimately yield nothing. Saying so is the difference between
	// "nothing matches" and "ask again for more".
	switch {
	case returned == 0 && total > 0 && result.CursorContinuation && result.NextCursor == "":
		notes = append(notes, cursorExhaustedNote)
	case returned == 0 && total > 0 && result.NextCursor != "":
		notes = append(notes, emptyPageMidWalkNote)
	case returned == 0 && total > 0:
		notes = append(notes, emptyPageNote)
	case total > returned:
		notes = append(notes, partialSetNote)
		if isPopulationIndex(index) {
			notes = append(notes, populationNote)
		}
		// Naming the route is half the point of saying the set is partial. Skipped
		// once a walk is under way, since the caller is holding the cursor, and above
		// the offset ceiling, where ceilingNote names this route and the backup both.
		if result.NextCursor == "" && !result.CursorContinuation && total <= offsetCeiling {
			notes = append(notes, cursorRouteNote)
		}
	}

	// Not on a walk already in progress: the caller is holding the cursor this would tell
	// them to use, and repeating it on every page is noise in a budgeted response.
	if total > offsetCeiling && !result.CursorContinuation {
		notes = append(notes, ceilingNote)
	}

	return notes
}

// windowedIndex resolves a window token to a concrete index name.
func windowedIndex(prefix, window string) (string, error) {
	if window == "" {
		window = defaultWindow
	}
	if !slices.Contains(indexWindows, window) {
		return "", fmt.Errorf("unknown window %q: expected one of %s", window, strings.Join(indexWindows, ", "))
	}
	return prefix + "-" + window, nil
}

// productResponse is the shape the four product tools return — search_target_intel,
// search_ip_intel, search_canaries and search_curated_exploits.
//
// It is a new contract rather than a reshaping of an existing one: these tools do
// not claim to hand back a raw /v3/index envelope, so they are free to report what
// they did. The rows in Data are still passed through verbatim.
type productResponse struct {
	envelope
	Index string            `json:"index"`
	Data  []json.RawMessage `json:"data"`
}

// productLimit clamps a requested row count to the upstream maximum, falling back to
// the tool's default when unset. The defaults are deliberately not 1: every question
// these indices answer is about a population, and a single row is a misleading
// answer to it rather than merely a small one.
func productLimit(requested, fallback int) int {
	if requested <= 0 {
		return fallback
	}
	return min(requested, maxProductLimit)
}

// newProductResponse assembles a response from an index result, attaching the notes that
// stop a sample being read as the complete set.
//
// Response size is not this function's concern: capResult bounds every tool's payload on
// the way out, so what is assembled here is the complete result and the notes describe
// what the API did, not what MCP did to fit it.
func newProductResponse(index string, result *client.IndexQueryResult) productResponse {
	response := productResponse{
		envelope: newEnvelope(len(result.Data), result.Total, result.NextCursor),
		Index:    index,
		Data:     result.Data,
	}
	response.Notes = indexNotes(index, result)

	return response
}
