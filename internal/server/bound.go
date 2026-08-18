package server

import "encoding/json"

// maxResponseBytes bounds a serialized tool response at roughly 20k tokens.
//
// `limit` bounds the number of rows, not their size, and record sizes vary
// enormously between indices: a single record from one index can outweigh a full
// page from another. Without a byte bound a broad query can consume most of a
// client's context, so rows are dropped whole until the response fits and the count
// dropped is reported.
const maxResponseBytes = 80_000

// rowBound describes a response whose row list may be trimmed to fit a byte budget.
type rowBound struct {
	// Envelope is the full response, rows included. It is marshalled once to
	// measure the fixed overhead around Rows, so the budget accounts for whatever
	// notes and metadata the caller has already attached.
	Envelope any

	// Rows are the records under consideration, carried raw so they need no
	// re-encoding to measure.
	Rows []json.RawMessage

	// MaxBytes is the ceiling for the serialized envelope. Zero means maxResponseBytes.
	MaxBytes int

	// Identify optionally names a dropped row — a CVE ID, an IP, whatever lets the
	// caller fetch it individually afterwards. Returning "" omits the row from Names.
	Identify func(json.RawMessage) string

	// MaxNamed caps how many dropped rows are named, so a large drop cannot itself
	// flood the response. Zero means no names are collected.
	MaxNamed int
}

// boundResult is the outcome of trimming: the rows that fit, how many did not, and
// the names of those that did not (up to MaxNamed).
type boundResult struct {
	Kept    []json.RawMessage
	Dropped int
	Names   []string
}

// boundRows drops whole rows until the marshalled envelope fits inside the budget.
//
// Rows are never abridged: a partial record would be indistinguishable from a
// complete one and could be read as authoritative. An oversized row is skipped
// rather than ending the walk, so one enormous record cannot hide the smaller ones
// behind it, which is why keeping "at least one row" is not a safe floor.
//
// The caller is responsible for assigning Kept back onto its response and for
// wording whatever note explains the drop; the phrasing that helps a model recover
// is specific to the tool, so this returns facts rather than prose.
func boundRows(b rowBound) boundResult {
	if len(b.Rows) == 0 {
		return boundResult{Kept: b.Rows}
	}

	maxBytes := b.MaxBytes
	if maxBytes <= 0 {
		maxBytes = maxResponseBytes
	}

	encoded, err := json.Marshal(b.Envelope)
	if err != nil || len(encoded) <= maxBytes {
		return boundResult{Kept: b.Rows}
	}

	// Budget only the rows; the surrounding envelope and notes are small and fixed.
	budget := maxBytes - (len(encoded) - rowsSize(b.Rows))
	kept := make([]json.RawMessage, 0, len(b.Rows))
	var names []string
	used := 0

	for _, raw := range b.Rows {
		size := len(raw) + 1 // the comma that joins it to the previous row
		if used+size > budget {
			if b.Identify != nil && len(names) < b.MaxNamed {
				if name := b.Identify(raw); name != "" {
					names = append(names, name)
				}
			}
			continue
		}
		used += size
		kept = append(kept, raw)
	}

	return boundResult{
		Kept:    kept,
		Dropped: len(b.Rows) - len(kept),
		Names:   names,
	}
}

// rowsSize reports the serialized size of the row list. Raw records need no
// re-encoding, so this is just their lengths plus the separators.
func rowsSize(data []json.RawMessage) int {
	size := 2 // the enclosing brackets
	for _, raw := range data {
		size += len(raw) + 1
	}
	return size
}
