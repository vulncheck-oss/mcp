package server

// envelope is the core every record-returning tool carries alongside its rows.
//
// It exists because the twelve tools that return API records grew their reporting
// separately: the six added after #46 carry a full account of what happened to a query,
// and the six from the first release carried none, so an empty page and a genuine no-match
// were indistinguishable on most of them.
//
// Tool-specific fields stay with their tools rather than moving here. `index` records which
// index a product tool chose on the caller's behalf, and `vendors_tried` is the audit trail
// of a case-variant retry — facts only those tools can report, and flattening them into a
// common shape would delete real information to buy symmetry.
//
// Each tool declares its own Data field and embeds this before it, so the core marshals
// ahead of the rows. Data is not part of the core because its element type differs per
// tool, and a generic would buy nothing: the field is one line either way.
//
// Do not embed this alongside another embedded struct carrying the same JSON names.
// encoding/json drops every conflicting name at the same depth and returns no error, so
// `total` and `next_cursor` would vanish silently.
type envelope struct {
	// Returned is how many rows the payload actually carries.
	//
	// Deliberately not omitempty. Zero is the single most important value it reports —
	// "this query matched nothing" as distinct from "this field is absent because
	// something went wrong" — and it is the field capResult's correctReturned rewrites
	// after trimming rows, which it only does for a tool that already carries it.
	Returned int `json:"returned"`

	// Total is how many rows matched upstream, which stays true when rows are trimmed for
	// size. total > returned is the signal that this is a page or a sample rather than
	// the whole set. Not omitempty, for the same reason as Returned.
	//
	// Unpaginated tools set it to len(data), which is truthful rather than padding: after
	// trimming, returned drops and total does not, so the gap still reports withholding.
	Total int `json:"total"`

	// NextCursor is omitempty because its absence is meaningful and unambiguous: there is
	// no next page. Unlike a zero count, an empty cursor cannot be read as a missing field.
	NextCursor string `json:"next_cursor,omitempty"`

	// Notes report what the API did to the query — filters it ignored, a page that is
	// empty for a reason other than absence, a total beyond what paging can reach.
	//
	// What MCP did to the response belongs in response_size instead. The split is
	// deliberate: one describes the answer, the other the transport.
	Notes []string `json:"notes,omitempty"`
}

// newEnvelope fills the core from a row count, a total and a cursor, so the nine tools that
// build one cannot drift in how they do it.
func newEnvelope(returned, total int, cursor string) envelope {
	return envelope{Returned: returned, Total: total, NextCursor: cursor}
}

// The vocabulary below is shared across tools rather than per-endpoint, because "these rows
// are not the whole answer" is the same fact whichever tool reports it. Each tool adds its
// own route clause, since how to reach the rest is the part that differs.
const (
	// partialSetNote is true of every tool: the rows are one page of a larger match set,
	// so the count in front of the caller is not the answer to "how many".
	partialSetNote = "these rows are one page of a larger match set, and total is the size of the " +
		"whole of it — report total rather than counting the rows returned"

	// cursorRouteNote names the route for tools that page by cursor but only issue one
	// when asked, so a response that carries no next_cursor does not reveal that a route
	// exists at all.
	cursorRouteNote = "to reach the rest, set start_cursor true on the first call and pass each " +
		"next_cursor back as cursor"
)
