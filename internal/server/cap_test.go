package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bulkyRecord builds a record whose weight is in one long array, like the enriched
// vulnerability records this contract exists for.
func bulkyRecord(id string, refs int) map[string]any {
	references := make([]any, refs)
	for i := range references {
		references[i] = map[string]any{
			"url":  fmt.Sprintf("https://example.test/advisory/%s/%d", id, i),
			"tags": []any{"vendor-advisory", "patch"},
		}
	}
	return map[string]any{
		"cve":        id,
		"references": references,
	}
}

// payloadText returns the record payload from a tool result — always the first content
// part, whether or not a size report follows it.
func payloadText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, result.Content)
	text, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	return text.Text
}

// sizeReport returns the report a tool attaches when it shortened a response, or nil when
// the response was within budget and returned untouched.
func sizeReport(t *testing.T, result *mcp.CallToolResult) *capReport {
	t.Helper()
	if len(result.Content) < 2 {
		return nil
	}
	text, ok := result.Content[1].(*mcp.TextContent)
	require.True(t, ok)
	var report capReport
	require.NoError(t, json.Unmarshal([]byte(text.Text), &report))
	return &report
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return out
}

func TestCapResponse_UnderBudgetIsByteIdentical(t *testing.T) {
	encoded := mustMarshal(t, map[string]any{
		"data":  []any{map[string]any{"cve": "CVE-2024-1", "references": []any{"a", "b"}}},
		"total": 1,
	})

	out, report := capResponse(encoded)

	assert.Nil(t, report, "a response within budget is not reported on")
	assert.Equal(t, string(encoded), string(out), "must be returned byte for byte, not re-encoded")
}

func TestCapResponse_SingleOversizedRecordKeepsTheRecord(t *testing.T) {
	// The shape of #3109: one document per CVE, far over budget, with no row count that
	// could bound it.
	encoded := mustMarshal(t, map[string]any{
		"data":  []any{bulkyRecord("CVE-2021-44228", 2457)},
		"total": 1,
	})
	require.Greater(t, len(encoded), 7*defaultResponseBudget)

	out, report := capResponse(encoded)
	require.NotNil(t, report)

	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	assert.Equal(t, 2457, report.Capped["/data/-/references"],
		"the array's true length must be reported, or a shortened array reads as complete")
	assert.Contains(t, arrayLadder, report.ArrayLimit)
	assert.Zero(t, report.RowsReturned, "the record must be kept, not removed")

	var payload struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	require.Len(t, payload.Data, 1, "the record survives; only its arrays are shortened")
	assert.Equal(t, "CVE-2021-44228", payload.Data[0]["cve"])
	assert.Equal(t, 1, payload.Total, "the envelope is untouched")
	assert.Len(t, payload.Data[0]["references"], report.ArrayLimit)
}

func TestCapResponse_ManyRowsAreThinnedNotDropped(t *testing.T) {
	// The case nothing handles today: boundRows would discard most of these rows where
	// shortening their arrays keeps all of them.
	rows := make([]any, 100)
	for i := range rows {
		rows[i] = bulkyRecord(fmt.Sprintf("CVE-2024-%04d", i), 60)
	}
	encoded := mustMarshal(t, map[string]any{"data": rows, "total": 100})

	out, report := capResponse(encoded)
	require.NotNil(t, report)

	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	assert.Zero(t, report.RowsReturned, "no row should have been removed")
	assert.NotContains(t, report.Capped, "/data", "the row list itself must not be trimmed")

	var payload struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	assert.Len(t, payload.Data, 100, "all rows survive, thinned")
}

func TestCapResponse_RowsAreGreedyFilledNotLaddered(t *testing.T) {
	// Rows with no inner arrays to shorten, so the only lever is removing rows. The count
	// kept must be "as many as fit" rather than a rung of the array ladder.
	rows := make([]any, 400)
	for i := range rows {
		rows[i] = map[string]any{
			"cve":         fmt.Sprintf("CVE-2024-%04d", i),
			"description": strings.Repeat("x", 400),
		}
	}
	encoded := mustMarshal(t, map[string]any{"data": rows, "total": 400})

	out, report := capResponse(encoded)
	require.NotNil(t, report)

	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	assert.Equal(t, 400, report.Capped["/data"], "the row list's true length is reported")
	assert.NotContains(t, arrayLadder, report.RowsReturned,
		"a row count that lands on a ladder rung suggests rows were snapped, not filled")
	assert.Positive(t, report.RowsReturned)

	// Adding one more row must exceed the budget, which is what "as many as fit" means.
	var payload struct {
		Data []any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	require.Len(t, payload.Data, report.RowsReturned)
	assert.Greater(t, len(mustMarshal(t, map[string]any{
		"data":  append(payload.Data, rows[report.RowsReturned]),
		"total": 400,
	})), defaultResponseBudget)
}

func TestCapResponse_RemovedRowsAreNamed(t *testing.T) {
	rows := make([]any, 300)
	for i := range rows {
		rows[i] = map[string]any{
			"cve":         fmt.Sprintf("CVE-2024-%04d", i),
			"description": strings.Repeat("y", 500),
		}
	}
	encoded := mustMarshal(t, map[string]any{"data": rows, "total": 300})

	_, report := capResponse(encoded)
	require.NotNil(t, report)

	names := report.RemovedIDs["/data"]
	require.NotEmpty(t, names, "a count says records are missing; names say which")
	assert.LessOrEqual(t, len(names), maxNamedRows)
	assert.Equal(t, fmt.Sprintf("CVE-2024-%04d", report.RowsReturned), names[0],
		"naming starts at the first removed row")
}

func TestCapResponse_RowsAreAContiguousRun(t *testing.T) {
	// Rows whose bulk is in arrays: the probe shrinks the leading row enough to fit, so
	// nothing is skipped and the result is a plain prefix.
	rows := []any{bulkyRecord("CVE-2024-BIG", 4000)}
	for i := range 50 {
		rows = append(rows, map[string]any{"cve": fmt.Sprintf("CVE-2024-%04d", i)})
	}
	encoded := mustMarshal(t, map[string]any{"data": rows, "total": len(rows)})

	out, report := capResponse(encoded)
	require.NotNil(t, report)
	assert.LessOrEqual(t, len(out), defaultResponseBudget)

	var payload struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	require.NotEmpty(t, payload.Data)
	assert.Equal(t, "CVE-2024-BIG", payload.Data[0]["cve"],
		"an array-heavy leading row is thinned, not skipped")
}

func TestCapResponse_UnshrinkableLeadingRowIsSkippedNotFatal(t *testing.T) {
	// The case the prefix rule has to bend for: a leading row whose bulk is a plain
	// string, which no array limit can shrink. Stopping at it would return an outline
	// while fifty perfectly good rows sat behind it.
	rows := []any{map[string]any{
		"cve":         "CVE-2024-BIG",
		"description": strings.Repeat("z", 2*defaultResponseBudget),
	}}
	for i := range 50 {
		rows = append(rows, map[string]any{"cve": fmt.Sprintf("CVE-2024-%04d", i)})
	}
	encoded := mustMarshal(t, map[string]any{"data": rows, "total": len(rows)})

	out, report := capResponse(encoded)
	require.NotNil(t, report)
	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	require.Nil(t, report.Outline, "rows fitted, so the floor must not be reached")

	var payload struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	require.NotEmpty(t, payload.Data)

	assert.Equal(t, "CVE-2024-0000", payload.Data[0]["cve"],
		"the unshrinkable leading row is skipped so the rows behind it survive")
	assert.Contains(t, report.RemovedIDs["/data"], "CVE-2024-BIG",
		"and it is named, so skipping it is recoverable rather than silent")

	// Everything after the skipped prefix is contiguous, which is what the cursor needs.
	for i, row := range payload.Data {
		assert.Equal(t, fmt.Sprintf("CVE-2024-%04d", i), row["cve"])
	}
}

func TestCapResponse_FlatStringListIsFilledNotLaddered(t *testing.T) {
	// get_cpe_cves returns a flat list of IDs under `cves`. Treating that as an inner
	// array would shorten it to a ladder rung; treating it as the row list returns as
	// many IDs as fit, which is two orders of magnitude more useful.
	cves := make([]any, 40_000)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%05d", i)
	}
	encoded := mustMarshal(t, map[string]any{
		"cpe":   "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		"cves":  cves,
		"total": 40_000,
	})

	out, report := capResponse(encoded)
	require.NotNil(t, report)

	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	assert.Equal(t, 40_000, report.Capped["/cves"])
	assert.Greater(t, report.RowsReturned, 1_000,
		"a flat ID list must be filled, not shortened to a ladder rung")

	var payload struct {
		CPE   string   `json:"cpe"`
		CVEs  []string `json:"cves"`
		Total int      `json:"total"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	assert.Equal(t, 40_000, payload.Total, "total comes from the API and stays correct")
	assert.Len(t, payload.CVEs, report.RowsReturned)
	assert.Equal(t, "CVE-2024-00000", payload.CVEs[0])
	assert.NotEmpty(t, report.RemovedIDs["/cves"], "a string row is its own identifier")
}

func TestCapResponse_BareRootArray(t *testing.T) {
	// identify_component marshals a bare top-level array, so its row list is the document
	// root rather than a named field.
	rows := make([]any, 500)
	for i := range rows {
		rows[i] = map[string]any{
			"identity": map[string]any{"product": strings.Repeat("p", 200)},
			"cpe":      fmt.Sprintf("cpe:2.3:a:vendor:product%d:*:*:*:*:*:*:*:*", i),
		}
	}
	encoded := mustMarshal(t, rows)

	out, report := capResponse(encoded)
	require.NotNil(t, report)

	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	var payload []map[string]any
	require.NoError(t, json.Unmarshal(out, &payload))
	assert.NotEmpty(t, payload)
	assert.Less(t, len(payload), len(rows))

	// The empty JSON Pointer names the document root correctly, but `{"": 500}` in the
	// report reads as a serialisation bug, and this map is the only thing telling a model
	// a visible count is not the real one.
	assert.NotContains(t, report.Capped, "")
	assert.Equal(t, len(rows), report.Capped[rootPointerLabel])
	assert.NotEmpty(t, report.RemovedIDs[rootPointerLabel])
}

func TestCapResponse_NonArrayBulkOutlines(t *testing.T) {
	// A single record oversized because of one enormous string. Neither the ladder nor
	// row removal can shrink it, and an empty row list on its own is not an answer.
	encoded := mustMarshal(t, map[string]any{
		"data": []any{map[string]any{
			"cve":         "CVE-2024-HUGE",
			"description": strings.Repeat("z", 4*defaultResponseBudget),
		}},
		"total": 1,
	})

	out, report := capResponse(encoded)
	require.NotNil(t, report)
	require.NotNil(t, report.Outline, "the floor must describe what did not fit")

	assert.LessOrEqual(t, len(out), defaultResponseBudget)
	assert.Equal(t, len(encoded), report.Outline.Bytes)
	require.NotEmpty(t, report.Outline.Shape)
	assert.Equal(t, "/data/-/description", report.Outline.Shape[0].Path,
		"the heaviest field is named first")
	assert.Greater(t, report.Outline.Shape[0].Percent, 50)
	assert.NotEmpty(t, report.Note)
}

func TestCapResponse_OutlineIsItselfWithinBudget(t *testing.T) {
	// The outline must not reproduce the problem it describes.
	record := bulkyRecord("CVE-2021-44228", 2457)
	record["description"] = strings.Repeat("z", 4*defaultResponseBudget)
	encoded := mustMarshal(t, map[string]any{"data": []any{record}, "total": 1})

	_, report := capResponse(encoded)
	require.NotNil(t, report)
	require.NotNil(t, report.Outline)

	assert.LessOrEqual(t, len(mustMarshal(t, report)), defaultResponseBudget)
	assert.LessOrEqual(t, len(report.Outline.Shape), outlineFields)
}

func TestCapResponse_LargeIntegersKeepPrecision(t *testing.T) {
	// Decoding to any turns numbers into float64 unless UseNumber is set, which silently
	// corrupts identifiers and timestamps beyond 2^53.
	rows := make([]any, 200)
	for i := range rows {
		rows[i] = map[string]any{
			"id":          int64(9007199254740993),
			"description": strings.Repeat("q", 400),
		}
	}
	encoded := mustMarshal(t, map[string]any{"data": rows, "total": 200})

	out, report := capResponse(encoded)
	require.NotNil(t, report)
	assert.Contains(t, string(out), "9007199254740993",
		"decode must use json.Number, or large integers are rounded")
}

func TestCapResponse_BudgetIsHonouredFromEnv(t *testing.T) {
	encoded := mustMarshal(t, map[string]any{
		"data":  []any{bulkyRecord("CVE-2024-1", 4000)},
		"total": 1,
	})

	out, report := capResponse(encoded)
	require.NotNil(t, report)
	require.LessOrEqual(t, len(out), defaultResponseBudget)
	atDefault := report.ArrayLimit

	t.Setenv(budgetEnv, "1500")
	out, report = capResponse(encoded)
	require.NotNil(t, report)
	assert.LessOrEqual(t, len(out), 1500)
	assert.Less(t, report.ArrayLimit, atDefault,
		"a smaller budget must force a shorter array limit")
}

func TestFindRowList(t *testing.T) {
	tests := []struct {
		name string
		body any
		want string
	}{
		{"data envelope", map[string]any{"data": []any{1, 2}, "total": 2}, "/data"},
		{"flat id list", map[string]any{"cpe": "x", "cves": []any{"a", "b"}}, "/cves"},
		{"bare root array", []any{1, 2, 3}, ""},
		{"no array at all", map[string]any{"total": 0}, noRowList},
		{
			// recentAdvisoriesResponse carries data and notes at the same level; size
			// has to break the tie or the digest's notes become the row list.
			name: "largest wins over sibling array",
			body: map[string]any{
				"data":  []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
				"notes": []any{"n"},
			},
			want: "/data",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, findRowList(tc.body))
		})
	}
}

func TestRowName(t *testing.T) {
	tests := []struct {
		name string
		row  any
		want string
	}{
		{"cve field", map[string]any{"cve": "CVE-2024-1"}, "CVE-2024-1"},
		{"id preferred over cve", map[string]any{"id": "CVE-2024-2", "cve": "other"}, "CVE-2024-2"},
		{"host address", map[string]any{"ip": "198.51.100.4"}, "198.51.100.4"},
		{"source address", map[string]any{"src_ip": "198.51.100.5"}, "198.51.100.5"},
		{"advisory metadata", map[string]any{
			"cveMetadata": map[string]any{"cveId": "CVE-2024-3"},
		}, "CVE-2024-3"},
		{"string row names itself", "CVE-2024-4", "CVE-2024-4"},
		{"nothing identifiable", map[string]any{"count": 3}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rowName(tc.row))
		})
	}
}

func TestCapResponse_EnvelopeMetadataSurvives(t *testing.T) {
	// The notes explain what the tool did and why. Shortening them to save a few dozen
	// bytes discards the explanation — including, absurdly, the note explaining the
	// shortening. Only arrays inside rows are on the ladder.
	rows := make([]any, 200)
	for i := range rows {
		rows[i] = bulkyRecord(fmt.Sprintf("CVE-2024-%04d", i), 80)
	}
	encoded := mustMarshal(t, map[string]any{
		"data":           rows,
		"total":          200,
		"notes":          []any{"first note", "second note", "third note"},
		"products_found": []any{"a", "b", "c", "d", "e"},
	})

	out, report := capResponse(encoded)
	require.NotNil(t, report)
	assert.LessOrEqual(t, len(out), defaultResponseBudget)

	assert.NotContains(t, report.Capped, "/notes")
	assert.NotContains(t, report.Capped, "/products_found")

	var payload struct {
		Notes         []string `json:"notes"`
		ProductsFound []string `json:"products_found"`
	}
	require.NoError(t, json.Unmarshal(out, &payload))
	assert.Len(t, payload.Notes, 3, "every note survives")
	assert.Len(t, payload.ProductsFound, 5)
}

func TestCapResponse_OutlineDescribesTheOriginalNotTheProbe(t *testing.T) {
	// The outline is all the caller gets on this path, so it has to describe the record
	// that arrived. Computing it from the probe — every array already cut to one element —
	// reported megabyte arrays as a few hundred bytes and, rated against the original
	// size, gave every field a share of zero.
	// Array bulk decides where the weight is; the string is what makes even a fully
	// stripped record too big, so the floor is reached with arrays still dominating.
	record := bulkyRecord("CVE-2021-44228", 20_000)
	record["description"] = strings.Repeat("z", 5_000)
	encoded := mustMarshal(t, map[string]any{"data": []any{record}, "total": 1})

	t.Setenv(budgetEnv, "2000")
	_, report := capResponse(encoded)
	require.NotNil(t, report)
	require.NotNil(t, report.Outline)

	require.NotEmpty(t, report.Outline.Shape)
	refs := report.Outline.Shape[0]
	assert.Equal(t, "/data/-/references", refs.Path, "the heaviest field is named first")
	assert.Equal(t, 20_000, refs.Items, "its true length, not the probe's one element")
	assert.Greater(t, refs.Bytes, defaultResponseBudget,
		"its true weight, not a few hundred bytes of shortened array")
	assert.Greater(t, refs.Percent, 50, "a share of the original, not zero")

	assert.Equal(t, len(encoded), report.Outline.Bytes)
	assert.Equal(t, 1, report.Outline.Rows)
}
