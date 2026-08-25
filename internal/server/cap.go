package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// defaultResponseBudget bounds a serialized tool response at roughly 8k tokens.
//
// `limit` bounds the number of rows, not their size, and record sizes vary enormously
// between indices: a single record from one index can outweigh a full page from another.
// The Log4Shell record on vulncheck-nvd2 is 876 KB on its own, so no row count can bound
// it — which is why the budget is measured in bytes and enforced by shortening arrays
// rather than by asking for fewer records.
//
// 30 KB is the figure validated across models and configurations: 50 KB was observed
// exhausting a context in practice, and 80 KB sits at the default rejection threshold of
// some clients with no headroom for a session that is already partly full.
const defaultResponseBudget = 30_000

// budgetEnv overrides the budget at startup.
//
// The real ceiling shifts from client to client with the model, the size of its context
// window and how full the session already is, so the right value is a deployment
// question rather than a fixed property of the data. Tuning it must not need a release.
//
// No floor or ceiling is enforced. The report and outline are small at any value an
// operator would plausibly set; the interesting direction is upward, since 80 KB is known
// to have worked; and a budget set absurdly low fails visibly and is recovered with the
// same dial.
const budgetEnv = "VULNCHECK_MCP_MAX_RESPONSE_BYTES"

// arrayLadder is the sequence of array-length caps tried, most generous first.
//
// The weight in an enriched record is in its long arrays, so shortening every array to the
// same length is the whole trick: one generic pass, no per-index or per-schema code. It
// reaches nested arrays as well as top-level ones, because for the largest records the top
// two arrays alone still leave the response oversized.
var arrayLadder = []int{50, 25, 12, 6, 3}

// floorLimit is the last rung. Below it there is nothing left to shorten, so a response
// that still does not fit is oversized for a reason arrays cannot fix.
const floorLimit = 1

// rootPointerLabel stands in for the empty JSON Pointer in the report.
//
// The empty pointer legitimately names the document root, which is the row list for a tool
// that marshals a bare top-level array. But `"capped": {"": 50}` reads as a serialisation
// bug, and this report is the only thing telling a model that a count it can see is not the
// real one — it cannot afford to look broken.
const rootPointerLabel = "(document root)"

// noRowList is the sentinel findRowList returns for a response with no array to trim.
// It is not a valid JSON Pointer, so it cannot collide with a real path — the empty
// pointer, which is valid, names the document root.
const noRowList = "\x00"

// maxNamedRows caps how many removed rows are named, so a large removal cannot itself
// flood the response.
const maxNamedRows = 25

// rowNameKeys are the fields consulted, in order, to name a row for removedIDs.
//
// This is one shared list rather than a per-tool accessor: vulnerability-keyed indices
// carry the CVE in `cve` while the exploit index puts it in `id`, host-oriented indices
// are keyed by address instead, and v4 advisories nest it under CVE 5.x metadata. A fixed
// precedence covers all of them, and a row matching none of them simply goes unnamed —
// the same outcome as a per-tool accessor returning "".
var rowNameKeys = []string{"id", "cve", "cve_id", "ip", "src_ip", "cpe", "purl"}

// capReport describes what was done to a response. It travels beside the payload rather
// than inside it, so the record itself gains and loses no fields.
type capReport struct {
	// Note comes first deliberately. This report is the only thing standing between a
	// shortened array and a model answering "five references" when there are 5,376: the
	// payload carries no truncation signal of its own, by design, because adding one
	// would alter the record. A reader skimming this part must hit the warning before
	// the machine metadata, not after it.
	Note string `json:"note"`

	OriginalBytes int `json:"original_bytes"`
	Bytes         int `json:"bytes"`

	// ArrayLimit is the length every array was shortened to. Zero means no array was
	// shortened, which happens when the row list alone was over budget.
	ArrayLimit int `json:"array_limit,omitempty"`

	// RowsReturned is set only when the row list was trimmed. It is not a limit — rows
	// are filled greedily — it saves the caller counting.
	RowsReturned int `json:"rows_returned,omitempty"`

	// Capped maps a JSON Pointer to the array's true length before shortening. Every
	// truncated array declares its real size here: a partial array is otherwise
	// indistinguishable from a complete one and can be read as authoritative.
	Capped map[string]int `json:"capped,omitempty"`

	// RemovedIDs names rows dropped from the row list, so they can be fetched
	// individually afterwards. A count says forty records are missing; this says which.
	RemovedIDs map[string][]string `json:"removed_ids,omitempty"`

	// Outline describes a response that could not be shortened at all, because its bulk
	// is not in arrays. Returning nothing but an empty row list is not a usable answer.
	Outline *outline `json:"outline,omitempty"`
}

// responseBudget reports the byte budget, honouring the environment override.
func responseBudget() int {
	if raw := os.Getenv(budgetEnv); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return defaultResponseBudget
}

// capResponse bounds a serialized tool response, returning the payload to send and a
// report of what was done to it. A nil report means the response was already within
// budget and is returned byte for byte.
//
// Nothing about any index, tool or record type appears here or is passed in: the walk is
// generic over decoded JSON, so it covers every index today, anything added later, and any
// future oversized record.
func capResponse(encoded []byte) ([]byte, *capReport) {
	budget := responseBudget()
	if len(encoded) <= budget {
		return encoded, nil
	}

	// Decoding is the expensive step and is reached only above budget. UseNumber is
	// required: without it every number becomes a float64 and large integers lose
	// precision on the way back out.
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		// The caller just marshalled this, so failure is not expected. Returning the
		// response unchanged is wrong but honest; silently emitting nothing is worse.
		return encoded, nil
	}

	rowPath := findRowList(root)

	// Probe the floor before descending. Shortening arrays further never makes a response
	// larger, so if the shortest rung does not fit, no rung does — and each rung costs a
	// full re-encode of a structure that may be very large. This turns the worst case,
	// where the bulk is the row list rather than the arrays inside rows, from seven
	// encodes into two.
	probe, probeCapped := capTree(root, floorLimit, rowPath)
	probeBytes, err := json.Marshal(probe)
	if err != nil {
		return encoded, nil
	}

	if len(probeBytes) <= budget {
		// Some rung fits. Find the most generous one, so no more detail is discarded
		// than the budget actually requires.
		for _, limit := range arrayLadder {
			candidate, capped := capTree(root, limit, rowPath)
			out, err := json.Marshal(candidate)
			if err != nil {
				continue
			}
			if len(out) <= budget {
				return out, &capReport{
					OriginalBytes: len(encoded),
					Bytes:         len(out),
					ArrayLimit:    limit,
					Capped:        capped,
					Note:          recordCappedNote(limit),
				}
			}
		}
		return probeBytes, &capReport{
			OriginalBytes: len(encoded),
			Bytes:         len(probeBytes),
			ArrayLimit:    floorLimit,
			Capped:        probeCapped,
			Note:          recordCappedNote(floorLimit),
		}
	}

	// Arrays alone cannot bring this within budget, so rows have to go.
	return fillRows(encoded, root, probe, probeCapped, rowPath, budget)
}

// findRowList reports the JSON Pointer of the response's row list, or "" if it has none.
//
// The row list is the largest top-level array by serialized size. It is derived rather
// than declared because the tools do not agree on where it lives: most carry rows under
// `data`, one returns a flat list of CVE IDs under `cves`, and one marshals a bare array
// at the document root. An outer array always contains its children, so the outermost is
// always the largest, and size breaks the tie against small sibling arrays such as notes.
func findRowList(root any) string {
	if _, ok := root.([]any); ok {
		return "" // the document root is the row list; the empty pointer names it
	}

	obj, ok := root.(map[string]any)
	if !ok {
		return noRowList // no row list at all
	}

	best, bestSize := noRowList, 0
	// Sorted so a tie between two equally sized arrays resolves the same way every time.
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if _, ok := obj[k].([]any); !ok {
			continue
		}
		encoded, err := json.Marshal(obj[k])
		if err != nil {
			continue
		}
		if len(encoded) > bestSize {
			best, bestSize = "/"+escapeToken(k), len(encoded)
		}
	}
	return best
}

// capTree copies a decoded response with every array shortened to limit, and reports the
// true length of each array it shortened.
//
// The row list is exempt: it is shortened by fillRows, greedily, because it is a single
// array where "as many as fit" is both simpler and strictly better than snapping to a
// rung. Arrays *inside* rows are shortened here, which is what lets a hundred records
// survive thinned rather than sixty of them being discarded whole.
func capTree(root any, limit int, rowPath string) (any, map[string]int) {
	capped := map[string]int{}
	out := capValue(root, limit, "", rowPath, capped)
	if len(capped) == 0 {
		return out, nil
	}
	return out, capped
}

// exemptArray reports whether an array is outside the ladder's remit.
//
// Two are: the row list, which is trimmed greedily by fillRows instead, and any array
// alongside it at the top level of the envelope. Those siblings are the response's own
// metadata — notes, the vendor spellings tried, the products found — which explain what the
// tool did and are already bounded where they are built. Shortening them discards an
// explanation to save a few dozen bytes, and the note explaining the shortening is exactly
// what gets lost.
func exemptArray(path, rowPath string) bool {
	if path == rowPath {
		return true
	}
	// A top-level field has a single-segment pointer; anything inside a row is deeper.
	return strings.Count(path, "/") == 1
}

func capValue(v any, limit int, path, rowPath string, capped map[string]int) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = capValue(child, limit, path+"/"+escapeToken(k), rowPath, capped)
		}
		return out

	case []any:
		// "/-" addresses every element of an array, so one report entry covers a field
		// however many rows carry it.
		childPath := path + "/-"

		keep := len(t)
		if !exemptArray(path, rowPath) && keep > limit {
			keep = limit
			// Report the longest instance seen: for a single-document response it is
			// exact, and across rows the longest is the one worth knowing about.
			if got := len(t); got > capped[path] {
				capped[path] = got
			}
		}

		out := make([]any, 0, keep)
		for _, child := range t[:keep] {
			out = append(out, capValue(child, limit, childPath, rowPath, capped))
		}
		return out

	default:
		return v
	}
}

// fillRows trims the row list to as many rows as fit, in order.
//
// Rows are kept as a contiguous run, with one exception at the front: rows that do not fit
// are skipped until the first one is kept, and after that the first row that does not fit
// ends the walk.
//
// The exception exists because a single enormous leading record would otherwise hide every
// smaller one behind it, returning an outline where perfectly good rows would have fitted —
// the empty answer this contract exists to avoid. The contiguity that matters is at the
// tail, where the cursor picks up; a skipped prefix is named in removed_ids and so stays
// recoverable.
func fillRows(encoded []byte, root, probe any, probeCapped map[string]int, rowPath string, budget int) ([]byte, *capReport) {
	rows, ok := rowsAt(probe, rowPath)
	if !ok || len(rows) == 0 {
		// Nothing to trim and still over budget: the bulk is not in arrays at all.
		return outlineOnly(encoded, root, probe, rowPath)
	}

	// Measure the envelope with an empty row list, so the budget accounts for whatever
	// else the response carries around the rows.
	empty, err := json.Marshal(setRowsAt(probe, rowPath, []any{}))
	if err != nil {
		return outlineOnly(encoded, root, probe, rowPath)
	}

	used := 0
	overhead := len(empty)
	kept := make([]any, 0, len(rows))
	removed := make([]any, 0)
	for i := range rows {
		size, err := json.Marshal(rows[i])
		// +1 for the comma joining this row to the previous one.
		if err != nil || overhead+used+len(size)+1 > budget {
			// Once a row has been kept, stop: the remainder is then a contiguous tail,
			// which is the only shape that can be reasoned about against a cursor.
			//
			// Before that, keep looking. One enormous leading record must not hide every
			// smaller one behind it — returning an outline where a perfectly good row
			// would have fit is exactly the empty answer this contract exists to avoid.
			if len(kept) > 0 {
				removed = append(removed, rows[i:]...)
				break
			}
			removed = append(removed, rows[i])
			continue
		}
		used += len(size) + 1
		kept = append(kept, rows[i])
	}

	if len(kept) == 0 {
		return outlineOnly(encoded, root, setRowsAt(probe, rowPath, rows), rowPath)
	}

	body := setRowsAt(probe, rowPath, kept)
	out, err := json.Marshal(body)
	if err != nil {
		return outlineOnly(encoded, root, body, rowPath)
	}

	capped := probeCapped
	if capped == nil {
		capped = map[string]int{}
	}
	capped[reportPath(rowPath)] = len(rows)

	report := &capReport{
		OriginalBytes: len(encoded),
		Bytes:         len(out),
		RowsReturned:  len(kept),
		Capped:        capped,
		Note:          rowsTrimmedNote(len(kept), len(rows)),
	}
	if names := nameRows(removed); len(names) > 0 {
		report.RemovedIDs = map[string][]string{reportPath(rowPath): names}
	}
	// ArrayLimit is only meaningful if arrays were in fact shortened.
	if len(probeCapped) > 0 {
		report.ArrayLimit = floorLimit
	}
	return out, report
}

// outlineOnly handles a response that no amount of shortening brings within budget: not one
// row survives even with every array cut to a single element. The shape and weight of what
// did not fit is returned instead, because an empty row list on its own is not an answer.
//
// The outline is taken from root — the response as it arrived — and never from the probe.
// Describing the already-shortened tree would report an array as a few hundred bytes when
// it is really megabytes, and rate it against the original size so every share rounds to
// zero. This is the one path where the report is all the caller gets, so it has to describe
// the record that actually exists.
func outlineOnly(encoded []byte, root, probe any, rowPath string) ([]byte, *capReport) {
	shape := outlineResponse(root, rowPath, len(encoded))
	body := setRowsAt(probe, rowPath, []any{})
	out, err := json.Marshal(body)
	if err != nil {
		out = []byte(`{}`)
	}
	return out, &capReport{
		OriginalBytes: len(encoded),
		Bytes:         len(out),
		Outline:       shape,
		Note: fmt.Sprintf("NO RECORDS ARE INCLUDED IN THIS RESPONSE. It was %d bytes, and not "+
			"one record fits the context budget even with every array cut to a single item. "+
			"outline below reports the size of the response and where its weight sits, so you "+
			"can see what was withheld — it is a description of the data, not the data. Fetch "+
			"the record via the API or CLI, which are not bounded this way.", len(encoded)),
	}
}

// reportPath renders a pointer for the report, naming the document root legibly.
func reportPath(path string) string {
	if path == "" {
		return rootPointerLabel
	}
	return path
}

// rowsAt returns the row list addressed by path.
func rowsAt(root any, path string) ([]any, bool) {
	if path == noRowList {
		return nil, false
	}
	if path == "" {
		rows, ok := root.([]any)
		return rows, ok
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, false
	}
	rows, ok := obj[unescapeToken(strings.TrimPrefix(path, "/"))].([]any)
	return rows, ok
}

// setRowsAt replaces the row list addressed by path, returning the new root.
//
// It returns rather than mutates because a bare top-level array *is* the root: there is no
// enclosing object to write into, so replacing it in place is impossible.
func setRowsAt(root any, path string, rows []any) any {
	switch path {
	case "":
		return rows
	case noRowList:
		return root
	}
	if obj, ok := root.(map[string]any); ok {
		obj[unescapeToken(strings.TrimPrefix(path, "/"))] = rows
	}
	return root
}

// nameRows identifies removed rows so they can be fetched individually afterwards.
func nameRows(rows []any) []string {
	names := make([]string, 0, min(len(rows), maxNamedRows))
	for _, row := range rows {
		if len(names) == maxNamedRows {
			break
		}
		if name := rowName(row); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// rowName reads a row's identifier from the shared candidate list.
func rowName(row any) string {
	switch t := row.(type) {
	case string:
		// A flat list of identifiers is its own name.
		return t
	case map[string]any:
		for _, key := range rowNameKeys {
			if s, ok := t[key].(string); ok && s != "" {
				return s
			}
		}
		// v4 advisories nest the CVE ID under CVE 5.x metadata rather than carrying it
		// at the top level.
		if meta, ok := t["cveMetadata"].(map[string]any); ok {
			if s, ok := meta["cveId"].(string); ok {
				return s
			}
		}
	}
	return ""
}

func recordCappedNote(limit int) string {
	return fmt.Sprintf("ARRAY COUNTS IN THIS RESPONSE ARE NOT REAL COUNTS: every array was "+
		"shortened to %d items to keep the response within a usable context budget. Read the "+
		"true length of each from capped below before reporting any quantity — an array showing "+
		"%d entries may have thousands. Nothing else was altered: the record is otherwise "+
		"complete and unmodified. For the full record, fetch it via the API or CLI", limit, limit)
}

func rowsTrimmedNote(kept, total int) string {
	return fmt.Sprintf("THIS IS NOT THE COMPLETE SET: %d of %d matching records are here, "+
		"trimmed to keep the response within a usable context budget. Do not report %d as a "+
		"count of anything. Each record returned is whole and unabridged. Narrow the query, or "+
		"fetch the records named in removed_ids individually — they will NOT appear on the next "+
		"page, because the cursor advances past this whole page", kept, total, kept)
}

// escapeToken encodes a JSON Pointer reference token (RFC 6901).
func escapeToken(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

func unescapeToken(s string) string {
	s = strings.ReplaceAll(s, "~1", "/")
	return strings.ReplaceAll(s, "~0", "~")
}

// capResult marshals a tool response, bounds it, and builds the MCP result.
//
// Every tool that returns API records ends with this single call, which is what keeps the
// twelve of them from growing separate answers to "the response is too big" again.
//
// When a response is shortened, the report travels as a second content part rather than
// inside the payload. The record itself therefore gains and loses no fields — only array
// lengths change — so a tool that claims to hand back an index record still does. The
// result is a successful one either way: an oversized response is not an error, and
// reporting it as one makes a model say the tool failed instead of reading what it got.
func capResult(v any) (*mcp.CallToolResult, any, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("serializing results: %w", err)
	}

	capped, report := capResponse(encoded)
	content := []mcp.Content{&mcp.TextContent{Text: string(capped)}}

	if report != nil {
		notice, err := json.Marshal(report)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing size report: %w", err)
		}
		content = append(content, &mcp.TextContent{Text: string(notice)})
	}

	return &mcp.CallToolResult{Content: content}, nil, nil
}
