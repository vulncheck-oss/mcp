package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
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
// The empty pointer legitimately names the document root, which is where the row list sits
// for a response that is itself an array. No tool marshals that shape — every one returns
// an object, because the report has to have somewhere to live — but the walk is generic
// over decoded JSON and the pointer helpers address the root regardless. `"capped": {"": 50}`
// reads as a serialisation bug, and this report is the only thing telling a model that a
// count it can see is not the real one — it cannot afford to look broken.
const rootPointerLabel = "(document root)"

// noRowList is the sentinel findRowList returns for a response with no array to trim.
// It is not a valid JSON Pointer, so it cannot collide with a real path — the empty
// pointer, which is valid, names the document root.
const noRowList = "\x00"

// maxNamedRows caps how many removed rows are named, so a large removal cannot itself
// flood the response.
const maxNamedRows = 25

// maxCappedPaths caps how many shortened arrays are reported.
//
// Capped holds one entry per distinct array path in the schema, not per row or per item
// dropped — the "-" in a pointer covers every element, so a thousand rows sharing a field
// collapse to one entry. Real records produce a handful: the largest seen across the live
// indices is 20 entries in 2 KB. But nothing bounds schema *width*, and the walk is sold as
// generic over indices added later; a record with 300 distinct arrays produced a 15 KB
// report, pushing payload plus report a third past the budget it exists to enforce. The
// same reason outlineFields and maxNamedRows are capped.
//
// The heaviest are kept, which is also the useful set: an array of 5,376 items is worth
// naming, one of 6 is not.
const maxCappedPaths = 25

// returnedKey is the envelope field naming how many rows are in the payload.
//
// Several tools compute it while assembling their response, which is before this layer
// trims anything, so left alone it asserts a count the payload contradicts. Unlike total,
// which counts what matched upstream and stays true, this is a fact about the rows actually
// present and has to move with them.
const returnedKey = "returned"

// responseSizeKey is the envelope field the report travels in.
//
// It sits beside data rather than in a separate content part so that the correcting count
// cannot be separated from the count it corrects: anything reading the payload reads both,
// or neither. #3109's constraint is about the API and its OpenAPI spec, not about what this
// server's own envelope may carry — and by the time this field is added the record's arrays
// have already been shortened, which is by far the larger alteration.
//
// A response that fits the budget never gets this field, so the common path stays exactly
// what the API returned.
const responseSizeKey = "response_size"

// rowNameKeys are the fields consulted, in order, to name a row for removedIDs.
//
// This is one shared list rather than a per-tool accessor: vulnerability-keyed indices
// carry the CVE in `cve` while the exploit index puts it in `id`, host-oriented indices
// are keyed by address instead, and v4 advisories nest it under CVE 5.x metadata. A fixed
// precedence covers all of them, and a row matching none of them simply goes unnamed —
// the same outcome as a per-tool accessor returning "".
var rowNameKeys = []string{"id", "cve", "cve_id", "ip", "src_ip", "cpe", "purl"}

// capReport describes what was done to a response. It travels in the envelope, beside the
// row list rather than inside any record, so the records themselves gain and lose no
// fields — only array lengths change.
type capReport struct {
	// Note comes first deliberately. This report is the only thing standing between a
	// shortened array and a model answering "five references" when there are 5,376: the
	// payload carries no truncation signal of its own, by design, because adding one
	// would alter the record. A reader skimming this part must hit the warning before
	// the machine metadata, not after it.
	Note string `json:"note"`

	OriginalBytes int `json:"original_bytes"`

	// ArrayLimit is the length every array was shortened to. Zero means no array was
	// shortened, which happens when the row list alone was over budget.
	ArrayLimit int `json:"array_limit,omitempty"`

	// RowsReturned is set only when the row list was trimmed. It is not a limit — rows
	// are filled greedily — it saves the caller counting.
	RowsReturned int `json:"rows_returned,omitempty"`

	// RowsRemoved is how many rows did not fit. RemovedIDs names at most maxNamedRows of
	// them, so without this a partial list reads as the complete set — and the note tells
	// the caller to go and fetch what it names.
	RowsRemoved int `json:"rows_removed,omitempty"`

	// Capped maps a JSON Pointer to the array's true length before shortening. Every
	// truncated array declares its real size here: a partial array is otherwise
	// indistinguishable from a complete one and can be read as authoritative.
	//
	// Bounded to the longest maxCappedPaths, so a wide schema cannot make the report the
	// thing that overruns the budget. ArraysShortened says how many there were in total,
	// because a silently partial list is the same defect this map exists to prevent.
	Capped map[string]int `json:"capped,omitempty"`

	// ArraysShortened is how many arrays were shortened in all. It is only set when that
	// exceeds what Capped lists.
	ArraysShortened int `json:"arrays_shortened,omitempty"`

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
		// The caller just marshalled this, so failure is not expected. capResult applies
		// a final budget check, so an oversized response cannot escape through here.
		return encoded, nil
	}

	// The report has to live somewhere, and nothing can be a sibling of a JSON array. A
	// response that is not an object could be shortened but not described, and arrays
	// shortened without a report are truncated data presented as complete. Bail here and
	// let capResult's backstop refuse it: no tool marshals that shape, and one that starts
	// to should fail loudly on its first oversized response rather than quietly mislead.
	if _, ok := root.(map[string]any); !ok {
		return encoded, nil
	}

	rowPath := findRowList(root)

	// Probe the floor before descending. Shortening arrays further never makes a response
	// larger, so if the shortest rung does not fit, no rung does — and each rung costs a
	// full re-encode of a structure that may be very large. This turns the worst case,
	// where the bulk is the row list rather than the arrays inside rows, from seven
	// encodes into two.
	probe, probeCapped, probeTotal := capTree(root, floorLimit, rowPath)
	probeOut, err := embed(probe, arraysCappedReport(len(encoded), floorLimit, probeCapped, probeTotal))
	if err != nil {
		return encoded, nil
	}

	if len(probeOut) <= budget {
		unembed(probe)

		// Some rung fits. Find the most generous one, so no more detail is discarded
		// than the budget actually requires.
		for _, limit := range arrayLadder {
			candidate, capped, total := capTree(root, limit, rowPath)
			report := arraysCappedReport(len(encoded), limit, capped, total)
			out, err := embed(candidate, report)
			if err != nil {
				continue
			}
			if len(out) <= budget {
				return out, report
			}
		}

		return probeOut, arraysCappedReport(len(encoded), floorLimit, probeCapped, probeTotal)
	}

	unembed(probe)

	// Arrays alone cannot bring this within budget, so rows have to go.
	return fillRows(encoded, root, probe, probeCapped, probeTotal, rowPath, budget)
}

// arraysCappedReport describes a response brought within budget by shortening arrays alone.
func arraysCappedReport(originalBytes, limit int, capped map[string]int, total int) *capReport {
	report := &capReport{
		OriginalBytes: originalBytes,
		ArrayLimit:    limit,
		Capped:        capped,
		Note:          recordCappedNote(limit),
	}
	if total > len(capped) {
		report.ArraysShortened = total
	}
	return report
}

// findRowList reports the JSON Pointer of the response's row list, or "" if it has none.
//
// The row list is the largest top-level array by serialized size. It is derived rather
// than declared because the tools do not agree on where it lives: most carry rows under
// `data` and one returns a flat list of CVE IDs under `cves`. An outer array always
// contains its children, so the outermost is always the largest, and size breaks the tie
// against small sibling arrays such as notes.
//
// The document-root case below is unreachable from today's handlers, which all return an
// object. It stays because this walk is documented as generic over decoded JSON, and the
// constraint that produced that guarantee is about where the report can live, not about
// what can be traversed.
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

// embed attaches the report to a candidate tree, marshals it, and returns the bytes.
//
// The report rides inside the payload rather than beside it, which is what makes the
// budget check honest: the bytes this returns are the bytes the caller emits, so a
// candidate that measures under budget is under budget. Sizing the payload alone and
// appending the report afterwards let a 29.6 KB payload plus a 2.5 KB report overshoot a
// 30 KB budget by 7% while every individual check passed.
//
// It also keeps the report inseparable from what it corrects. A `returned` count rewritten
// to match a trimmed payload is worth nothing if the correction can be read without it.
//
// A tree that is not a JSON object is refused rather than served. Nothing can be a sibling
// of an array, so a bare top-level array cannot carry the field, and shortening one while
// quietly dropping the report would emit truncated arrays presented as complete — the one
// outcome this mechanism exists to prevent. Every tool therefore returns an object; see
// identifyComponentResult, which exists only to satisfy this. The error routes to refuse,
// which emits the report and no data, so a shape that cannot be described is never served.
func embed(tree any, report *capReport) ([]byte, error) {
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("response is %T, not a JSON object, so it cannot carry a size report", tree)
	}
	if report != nil {
		obj[responseSizeKey] = report
	}

	out, err := json.Marshal(tree)
	if err != nil {
		delete(obj, responseSizeKey)
		return nil, err
	}
	return out, nil
}

// capTree copies a decoded response with every array shortened to limit, and reports the
// true length of each array it shortened, plus how many were shortened in all.
//
// The row list is exempt: it is shortened by fillRows, greedily, because it is a single
// array where "as many as fit" is both simpler and strictly better than snapping to a
// rung. Arrays *inside* rows are shortened here, which is what lets a hundred records
// survive thinned rather than sixty of them being discarded whole.

// unembed removes a report from a candidate that was measured and rejected, so the tree can
// be reused without carrying a stale one.
func unembed(tree any) {
	if obj, ok := tree.(map[string]any); ok {
		delete(obj, responseSizeKey)
	}
}

func capTree(root any, limit int, rowPath string) (any, map[string]int, int) {
	capped := map[string]int{}
	out := capValue(root, limit, "", rowPath, capped)
	if len(capped) == 0 {
		return out, nil, 0
	}
	return out, heaviestPaths(capped, maxCappedPaths), len(capped)
}

// heaviestPaths keeps the n longest arrays, so a wide schema cannot make the report itself
// the thing that overruns the budget.
func heaviestPaths(capped map[string]int, n int) map[string]int {
	if len(capped) <= n {
		return capped
	}

	paths := make([]string, 0, len(capped))
	for path := range capped {
		paths = append(paths, path)
	}
	// Longest first, then by path, so the same response always reports the same set.
	sort.Slice(paths, func(i, j int) bool {
		if capped[paths[i]] != capped[paths[j]] {
			return capped[paths[i]] > capped[paths[j]]
		}
		return paths[i] < paths[j]
	})

	kept := make(map[string]int, n)
	for _, path := range paths[:n] {
		kept[path] = capped[path]
	}
	return kept
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
func fillRows(encoded []byte, root, probe any, probeCapped map[string]int, probeTotal int, rowPath string, budget int) ([]byte, *capReport) {
	rows, ok := rowsAt(probe, rowPath)
	if !ok || len(rows) == 0 {
		// Nothing to trim and still over budget: the bulk is not in arrays at all.
		return outlineOnly(encoded, root, probe, rowPath)
	}

	// Measure the envelope with an empty row list, so the budget accounts for whatever
	// else the response carries around the rows. The report is measured with it: it is
	// part of what the caller receives, so it is part of what has to fit.
	empty, err := json.Marshal(setRowsAt(probe, rowPath, []any{}))
	if err != nil {
		return outlineOnly(encoded, root, probe, rowPath)
	}
	overhead := len(empty) + reportAllowance(len(encoded), rowPath, probeCapped, probeTotal, len(rows))

	used := 0
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

	// Rows are filled at the floor and the ladder is not re-climbed afterwards. That is
	// deliberate rather than an oversight: the row count here is the *maximum* that fits
	// at a limit of one, so no more generous limit can fit that many — climbing back is a
	// no-op. Trading rows for richer rows instead ("ten rows at twenty-five items rather
	// than eighteen at one") is a different objective needing an arbitrary parameter, and
	// there is no principled value for it. Heavy row removal yields thin rows, and the
	// report says so.

	body := setRowsAt(probe, rowPath, kept)
	correctReturned(body, len(kept))

	report := rowsTrimmedReport(len(encoded), rowPath, probeCapped, probeTotal, kept, removed, len(rows))
	out, err := embed(body, report)
	if err != nil {
		return outlineOnly(encoded, root, body, rowPath)
	}

	// The allowance is an estimate, so confirm rather than assume. Dropping the last row
	// is cheaper than re-running the walk and is bounded: one row cannot be short by more
	// than the allowance was wrong by.
	for len(out) > budget && len(kept) > 1 {
		unembed(body)
		removed = append([]any{kept[len(kept)-1]}, removed...)
		kept = kept[:len(kept)-1]
		body = setRowsAt(probe, rowPath, kept)
		correctReturned(body, len(kept))
		report = rowsTrimmedReport(len(encoded), rowPath, probeCapped, probeTotal, kept, removed, len(rows))
		out, err = embed(body, report)
		if err != nil {
			return outlineOnly(encoded, root, body, rowPath)
		}
	}

	return out, report
}

// rowsTrimmedReport describes a response that needed rows removed as well as arrays shortened.
func rowsTrimmedReport(originalBytes int, rowPath string, probeCapped map[string]int, probeTotal int, kept, removed []any, page int) *capReport {
	capped := make(map[string]int, len(probeCapped)+1)
	maps.Copy(capped, probeCapped)
	capped[reportPath(rowPath)] = page

	report := &capReport{
		OriginalBytes: originalBytes,
		RowsReturned:  len(kept),
		RowsRemoved:   len(removed),
		Capped:        capped,
		Note:          rowsTrimmedNote(len(kept), page, len(probeCapped) > 0),
	}
	if names := nameRows(removed); len(names) > 0 {
		report.RemovedIDs = map[string][]string{reportPath(rowPath): names}
	}
	// ArrayLimit is only meaningful if arrays were in fact shortened.
	if len(probeCapped) > 0 {
		report.ArrayLimit = floorLimit
	}
	if probeTotal > len(probeCapped) {
		report.ArraysShortened = probeTotal
	}
	return report
}

// reportAllowance estimates how much room the report will need, so rows are not filled into
// space the report then has to occupy. It is deliberately an estimate — the exact size
// depends on how many rows are kept, which is what is being decided — and fillRows confirms
// the real total afterwards.
func reportAllowance(originalBytes int, rowPath string, probeCapped map[string]int, probeTotal, page int) int {
	sample := rowsTrimmedReport(originalBytes, rowPath, probeCapped, probeTotal, nil, nil, page)
	// Names are the part that scales with what is removed, and they are bounded.
	sample.RemovedIDs = map[string][]string{reportPath(rowPath): make([]string, maxNamedRows)}
	encoded, err := json.Marshal(sample)
	if err != nil {
		return 0
	}
	// Each placeholder name marshals as "" but a real one is an identifier.
	return len(encoded) + maxNamedRows*24
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

	// The rows are about to be discarded wholesale, so they are named on the way out and
	// the envelope's own count is corrected to nothing. Leaving `returned` asserting forty
	// records beside an empty list is the contradiction this layer exists to prevent, in
	// its worst form — and rows that vanish unnamed are not recoverable at all.
	discarded, _ := rowsAt(probe, rowPath)
	body := setRowsAt(probe, rowPath, []any{})
	correctReturned(body, 0)

	report := &capReport{
		OriginalBytes: len(encoded),
		RowsRemoved:   len(discarded),
		Outline:       shape,
		Note: fmt.Sprintf("NO RECORDS ARE INCLUDED IN THIS RESPONSE. It was %d bytes, and not "+
			"one record fits the context budget even with every array cut to a single item. "+
			"outline below reports the size of the response and where its weight sits, so you "+
			"can see what was withheld — it is a description of the data, not the data. Any "+
			"per-page summary still in the payload, such as a breakdown by source, counts "+
			"records that are NOT here. Fetch the records named in removed_ids individually, "+
			"or fetch the data via the API or CLI, which are not bounded this way.", len(encoded)),
	}
	if names := nameRows(discarded); len(names) > 0 {
		report.RemovedIDs = map[string][]string{reportPath(rowPath): names}
	}

	out, err := embed(body, report)
	if err != nil {
		// The report is the entire answer on this path, so it must not be the thing that
		// gets dropped. capResult's backstop re-emits it on its own.
		return []byte(`{}`), report
	}
	return out, report
}

// correctReturned updates the envelope's row count to what the payload actually carries.
//
// Only a top-level numeric field is touched, and only when the tool already had one: this
// corrects a stale fact rather than adding one, so a tool that never reported a count does
// not start.
func correctReturned(root any, kept int) {
	obj, ok := root.(map[string]any)
	if !ok {
		return
	}
	if _, present := obj[returnedKey]; !present {
		return
	}
	if _, numeric := obj[returnedKey].(json.Number); !numeric {
		return
	}
	obj[returnedKey] = kept
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
// It returns rather than mutates because a response that is itself an array *is* the root:
// there is no enclosing object to write into, so replacing it in place is impossible.
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

// rowsTrimmedNote describes a trimmed row list. Rows reach this path only via the floor
// probe, so their arrays are shortened too whenever the record had any — claiming the
// records are whole would be false on exactly the path a reader hits first.
func rowsTrimmedNote(kept, page int, arraysShortened bool) string {
	note := fmt.Sprintf("THIS IS NOT THE COMPLETE SET: %d of the %d records on this page are "+
		"here, trimmed to keep the response within a usable context budget. Do not report %d "+
		"as a count of anything — total, in the payload, is how many matched. ", kept, page, kept)

	if arraysShortened {
		note += "The records that are here have also had every array shortened to a single " +
			"item: capped below gives each array's true length, so a count you can see in a " +
			"record is not the real one. "
	} else {
		note += "The records that are here are whole and unabridged. "
	}

	return note + "Any other per-page summary in the payload describes the page before it " +
		"was trimmed. Narrow the query, or fetch the records named in removed_ids " +
		"individually — they will NOT appear on the next page, because the cursor advances " +
		"past this whole page."
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
// A response within budget is returned exactly as it was marshalled. A shortened one gains
// a response_size field describing what was done to it, beside the data rather than in a
// separate content part, so that a corrected count cannot be separated from the count it
// corrects — anything reading the payload reads both, or neither.
//
// The result is one content part, always. That is what makes the budget check a single
// comparison against the bytes actually emitted, rather than an accounting exercise over
// parts that land in the same context but were measured apart.
//
// Either way the result is a successful one. An oversized response is not an error, and
// reporting it as one makes a model say the tool failed instead of reading what it got.
func capResult(v any) (*mcp.CallToolResult, any, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("serializing results: %w", err)
	}

	capped, report := capResponse(encoded)

	// A last backstop. capResponse has paths that give up and hand back what they were
	// given — a response it could not decode, a row list it could not address, a shape
	// that cannot carry the report at all — and each is individually defensible while
	// together they let an oversized or undescribed payload out.
	if len(capped) > responseBudget() {
		capped, _ = refuse(encoded, report)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(capped)}},
	}, nil, nil
}

// refuse replaces a response that could not be brought within budget with a report saying
// so. Emitting the oversized payload is the one outcome this mechanism exists to prevent,
// so when everything else has failed it emits nothing but the explanation.
//
// Whatever the failed attempt had already worked out is kept: an outline describing where
// the weight sits, and the identifiers of records that were dropped, are the only things
// standing between the caller and an unexplained empty answer.
func refuse(encoded []byte, prior *capReport) ([]byte, *capReport) {
	report := &capReport{OriginalBytes: len(encoded)}
	if prior != nil {
		report.Outline = prior.Outline
		report.RowsRemoved = prior.RowsRemoved
		report.RemovedIDs = prior.RemovedIDs
	}

	report.Note = refusalNote(len(encoded), report)
	out, err := json.Marshal(map[string]any{responseSizeKey: report})
	if err != nil {
		return []byte(`{}`), report
	}

	// A refusal that is itself over budget helps nobody; the outline is the expendable
	// part. The note is rebuilt afterwards, because what it should say depends on what
	// survived this trim rather than on what was carried into it.
	if len(out) > responseBudget() {
		report.Outline = nil
		report.RemovedIDs = nil
		report.Note = refusalNote(len(encoded), report)
		if out, err = json.Marshal(map[string]any{responseSizeKey: report}); err != nil {
			return []byte(`{}`), report
		}
	}

	return out, report
}

// refusalNote describes a refusal in terms of what it still carries.
//
// "Could not be reduced" is the right thing to say only when nothing survived. Saying it
// while handing over the identifiers of twenty-five fetchable records tells a model to give
// up on data it is holding the keys to, which is a worse failure than the size problem the
// refusal exists to report.
func refusalNote(originalBytes int, report *capReport) string {
	named := 0
	for _, names := range report.RemovedIDs {
		named += len(names)
	}

	switch {
	case named > 0:
		note := fmt.Sprintf("NO RECORDS ARE INCLUDED IN THIS RESPONSE: it was %d bytes and "+
			"nothing could be shortened enough to fit the context budget. This is not the "+
			"end of the road — removed_ids names %d", originalBytes, named)
		if report.RowsRemoved > named {
			note += fmt.Sprintf(" of the %d records that did not fit", report.RowsRemoved)
		} else {
			note += " of the records that did not fit"
		}
		note += ", and each can be fetched individually by that identifier."
		if report.Outline != nil {
			note += " outline reports where the response's weight sits, so you can see what " +
				"was withheld and narrow the query."
		}
		return note

	case report.Outline != nil:
		return fmt.Sprintf("NO DATA IS INCLUDED IN THIS RESPONSE: it was %d bytes and could "+
			"not be shortened enough to fit the context budget. outline reports where its "+
			"weight sits, so you can see what was withheld — it is a description of the data, "+
			"not the data. Narrow the query, or fetch this via the API or CLI, which are not "+
			"bounded this way.", originalBytes)

	default:
		return fmt.Sprintf("NO DATA IS INCLUDED IN THIS RESPONSE: it was %d bytes and could "+
			"not be reduced to fit the context budget at all. Narrow the query, or fetch this "+
			"via the API or CLI, which are not bounded this way.", originalBytes)
	}
}
