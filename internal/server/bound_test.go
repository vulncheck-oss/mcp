package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnvelope mirrors the shape every bounded tool response shares: a row list
// plus some fixed metadata that also has to fit inside the budget.
type testEnvelope struct {
	Data  []json.RawMessage `json:"data"`
	Total int               `json:"total"`
	Notes []string          `json:"notes,omitempty"`
}

// row builds a record of approximately size bytes, tagged with an id so drops can
// be attributed.
func row(id string, size int) json.RawMessage {
	pad := max(size-len(id)-20, 1)
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"p":%q}`, id, strings.Repeat("x", pad)))
}

func idOf(raw json.RawMessage) string {
	var r struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.ID
}

func TestBoundRows_LeavesResponsesThatAlreadyFit(t *testing.T) {
	rows := []json.RawMessage{row("a", 100), row("b", 100)}
	env := &testEnvelope{Data: rows, Total: 2}

	got := boundRows(rowBound{Envelope: env, Rows: rows, MaxBytes: 10_000})

	assert.Equal(t, 0, got.Dropped)
	assert.Empty(t, got.Names)
	assert.Len(t, got.Kept, 2)
}

func TestBoundRows_EmptyRowsIsANoOp(t *testing.T) {
	env := &testEnvelope{Total: 0}

	got := boundRows(rowBound{Envelope: env, Rows: nil, MaxBytes: 1})

	assert.Equal(t, 0, got.Dropped)
	assert.Empty(t, got.Kept)
}

func TestBoundRows_DropsWholeRowsUntilTheResponseFits(t *testing.T) {
	rows := make([]json.RawMessage, 20)
	for i := range rows {
		rows[i] = row(fmt.Sprintf("cve-%d", i), 1_000)
	}
	env := &testEnvelope{Data: rows, Total: 20}
	const budget = 5_000

	got := boundRows(rowBound{Envelope: env, Rows: rows, MaxBytes: budget, Identify: idOf, MaxNamed: 50})

	require.NotEmpty(t, got.Kept, "a budget larger than one row must keep some rows")
	assert.Equal(t, len(rows)-len(got.Kept), got.Dropped)

	// Every kept row is intact — trimming never abridges a record.
	for _, raw := range got.Kept {
		assert.True(t, json.Valid(raw), "kept rows must remain valid JSON")
	}

	env.Data = got.Kept
	encoded, err := json.Marshal(env)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(encoded), budget, "trimmed response must fit the budget")
}

// A single enormous record must not end the walk, or it would hide every smaller
// row behind it and the caller would see one row where it could have had many.
func TestBoundRows_SkipsAnOversizedRowAndKeepsTheSmallerOnesBehindIt(t *testing.T) {
	rows := []json.RawMessage{
		row("huge", 40_000),
		row("small-1", 200),
		row("small-2", 200),
	}
	env := &testEnvelope{Data: rows, Total: 3}

	got := boundRows(rowBound{Envelope: env, Rows: rows, MaxBytes: 2_000, Identify: idOf, MaxNamed: 10})

	assert.Equal(t, 1, got.Dropped)
	assert.Equal(t, []string{"huge"}, got.Names)

	kept := make([]string, 0, len(got.Kept))
	for _, raw := range got.Kept {
		kept = append(kept, idOf(raw))
	}
	assert.Equal(t, []string{"small-1", "small-2"}, kept)
}

func TestBoundRows_CapsHowManyDroppedRowsAreNamed(t *testing.T) {
	rows := make([]json.RawMessage, 30)
	for i := range rows {
		rows[i] = row(fmt.Sprintf("cve-%d", i), 2_000)
	}
	env := &testEnvelope{Data: rows, Total: 30}

	got := boundRows(rowBound{Envelope: env, Rows: rows, MaxBytes: 3_000, Identify: idOf, MaxNamed: 4})

	assert.Greater(t, got.Dropped, 4, "this budget must drop more rows than MaxNamed")
	assert.Len(t, got.Names, 4, "names are capped so a large drop cannot flood the response")
}

func TestBoundRows_CollectsNoNamesWithoutAnIdentifier(t *testing.T) {
	rows := []json.RawMessage{row("a", 5_000), row("b", 5_000)}
	env := &testEnvelope{Data: rows, Total: 2}

	got := boundRows(rowBound{Envelope: env, Rows: rows, MaxBytes: 1_000})

	assert.Positive(t, got.Dropped)
	assert.Empty(t, got.Names, "Identify is optional")
}

// The budget covers the whole envelope, so metadata the caller has already attached
// leaves less room for rows. Without this, a response with many notes could still
// overflow after trimming.
func TestBoundRows_AccountsForEnvelopeOverhead(t *testing.T) {
	rows := make([]json.RawMessage, 10)
	for i := range rows {
		rows[i] = row(fmt.Sprintf("r-%d", i), 500)
	}
	const budget = 4_000

	bare := boundRows(rowBound{Envelope: &testEnvelope{Data: rows, Total: 10}, Rows: rows, MaxBytes: budget})

	noisy := &testEnvelope{Data: rows, Total: 10, Notes: []string{strings.Repeat("n", 2_000)}}
	withNotes := boundRows(rowBound{Envelope: noisy, Rows: rows, MaxBytes: budget})

	assert.Less(t, len(withNotes.Kept), len(bare.Kept),
		"a bulkier envelope must leave room for fewer rows")

	noisy.Data = withNotes.Kept
	encoded, err := json.Marshal(noisy)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(encoded), budget)
}

func TestBoundRows_DefaultsToMaxResponseBytes(t *testing.T) {
	rows := make([]json.RawMessage, 200)
	for i := range rows {
		rows[i] = row(fmt.Sprintf("r-%d", i), 2_000)
	}
	env := &testEnvelope{Data: rows, Total: 200}

	got := boundRows(rowBound{Envelope: env, Rows: rows}) // MaxBytes unset

	assert.Positive(t, got.Dropped, "400 KB of rows must be trimmed against the default budget")

	env.Data = got.Kept
	encoded, err := json.Marshal(env)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(encoded), maxResponseBytes)
}

func TestRowsSize_MatchesTheSerializedRowList(t *testing.T) {
	rows := []json.RawMessage{row("a", 120), row("b", 340)}

	encoded, err := json.Marshal(rows)
	require.NoError(t, err)

	// rowsSize counts a separator after every row rather than between them, so it
	// overshoots by exactly one byte — deliberate, since it is used as a floor.
	assert.Equal(t, len(encoded)+1, rowsSize(rows))
}
