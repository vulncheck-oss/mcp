package server

import "github.com/vulncheck-oss/mcp/internal/client"

// The search_nvd_* tools serve VulnCheck's NVD API 2.0 compatible endpoints under
// /rest/json. They are positioned as a fallback in serverInstructions: search_cve stays
// the answer to "what is known about this CVE", and these are for questions about what
// NVD itself publishes, and for community tokens, which reach NVD's change history,
// match criteria and source list only through them.
//
// Every description says "any VulnCheck API token, including community" because that is
// what distinguishes these tools: the native index routes refuse most of the same data to
// a community token with an HTTP 402, and a model cannot otherwise tell the two apart.

// nvdCommunityClause ends every search_nvd_* description.
const nvdCommunityClause = "Works with any VulnCheck API token, including community."

// nvdDateClause describes the date filters, which every endpoint validates the same way.
const nvdDateClause = "Date filters are ISO-8601 (e.g. 2026-01-01T00:00:00.000), need both ends of a range, " +
	"and span at most 120 days."

// nvdStartIndexRouteNote is the route clause for search_nvd_sources, the one endpoint
// that has no cursor.
const nvdStartIndexRouteNote = "to reach the rest, call again with start_index advanced by the number of rows returned"

// nvdLimit applies a tool's default and ceiling to a requested page size.
func nvdLimit(requested, def, ceiling int32) int32 {
	if requested <= 0 {
		return def
	}
	if requested > ceiling {
		return ceiling
	}
	return requested
}

// nvdPage builds the client paging for a cursor-paged NVD tool.
func nvdPage(limit int32, startCursor bool, cursor string) client.NVDPage {
	return client.NVDPage{Limit: limit, StartCursor: startCursor, Cursor: cursor}
}

// nvdCursorEnvelope fills the core for a cursor-paged NVD tool, with the same notes
// search_cve gives a partial page: the rows are not the whole answer, and if no cursor
// came back the caller needs telling that one exists.
func nvdCursorEnvelope(returned, total int, nextCursor, cursorArg string) envelope {
	env := newEnvelope(returned, total, nextCursor)
	if total > returned {
		env.Notes = append(env.Notes, partialSetNote)
		if nextCursor == "" && cursorArg == "" {
			env.Notes = append(env.Notes, cursorRouteNote)
		}
	}
	return env
}
