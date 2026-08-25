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
	populationNote = "this index describes a population of hosts or events rather than one record " +
		"per CVE, so these rows are a sample and total is the size of the whole matching set — " +
		"report total rather than counting the rows returned"

	ceilingNote = "total exceeds the number of records reachable by paging (page x limit is capped " +
		"at 10000 upstream); for the full set use a backup of this index rather than paginating"

	emptyPageNote = "records match this query but none was returned on this page: the API applies the " +
		"filter to a page after slicing it, so a small limit can yield nothing while total is " +
		"non-zero. This is not an absence of data — retry with a larger limit"
)

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

// productResponse is the shape the three product tools return.
//
// It is a new contract rather than a reshaping of an existing one: these tools do
// not claim to hand back a raw /v3/index envelope, so they are free to report what
// they did. The rows in Data are still passed through verbatim.
type productResponse struct {
	Index      string            `json:"index"`
	Data       []json.RawMessage `json:"data"`
	Returned   int               `json:"returned"`
	Total      int               `json:"total"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
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
		Index:      index,
		Data:       result.Data,
		Total:      result.Total,
		NextCursor: result.NextCursor,
		Returned:   len(result.Data),
	}
	// An empty page with a non-zero total is not the same as no data, and must not be
	// reported as a sample: the filter is applied to a page after it is sliced, so a
	// small limit can legitimately yield nothing. Saying so is the difference between
	// "nothing matches" and "ask again for more".
	switch {
	case response.Returned == 0 && response.Total > 0:
		response.Notes = append(response.Notes, emptyPageNote)
	case response.Total > response.Returned:
		response.Notes = append(response.Notes, populationNote)
	}
	if response.Total > offsetCeiling {
		response.Notes = append(response.Notes, ceilingNote)
	}

	return response
}
