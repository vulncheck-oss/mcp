package server

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// captureQuery returns a mock whose SearchIndex records the query it was handed, so
// tests can assert the tool mapped its arguments onto the right upstream parameters.
func captureQuery(got *client.SearchIndexQuery, resp *client.IndexQueryResult) *mockClient {
	return &mockClient{
		searchIndexFn: func(_ context.Context, q client.SearchIndexQuery) (*client.IndexQueryResult, error) {
			*got = q
			if resp != nil {
				return resp, nil
			}
			return &client.IndexQueryResult{Data: []json.RawMessage{}}, nil
		},
	}
}

func decodeProduct(t *testing.T, text string) productResponse {
	t.Helper()
	var got productResponse
	require.NoError(t, json.Unmarshal([]byte(text), &got))
	return got
}

func TestWindowedIndex(t *testing.T) {
	tests := []struct {
		window string
		want   string
		errs   bool
	}{
		{window: "", want: "ipintel-3d"},
		{window: "3d", want: "ipintel-3d"},
		{window: "10d", want: "ipintel-10d"},
		{window: "30d", want: "ipintel-30d"},
		{window: "90d", want: "ipintel-90d"},
		{window: "7d", errs: true},
		{window: "30", errs: true},
		{window: "ipintel-30d", errs: true},
	}

	for _, tt := range tests {
		t.Run("window="+tt.window, func(t *testing.T) {
			got, err := windowedIndex(ipIntelPrefix, tt.window)
			if tt.errs {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "3d, 10d, 30d, 90d",
					"the error must name the valid windows so the caller can retry")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCanaryIndex_AllSelectsTheUnwindowedIndex(t *testing.T) {
	got, err := canaryIndex("all")
	require.NoError(t, err)
	assert.Equal(t, "vulncheck-canaries", got)

	got, err = canaryIndex("30d")
	require.NoError(t, err)
	assert.Equal(t, "vulncheck-canaries-30d", got)

	got, err = canaryIndex("")
	require.NoError(t, err)
	assert.Equal(t, "vulncheck-canaries-3d", got, "the default window is 3d")
}

func TestProductLimit(t *testing.T) {
	assert.Equal(t, 10, productLimit(0, 10), "unset falls back to the tool default")
	assert.Equal(t, 10, productLimit(-5, 10), "a negative limit falls back too")
	assert.Equal(t, 25, productLimit(25, 10))
	assert.Equal(t, maxProductLimit, productLimit(5000, 10), "clamped to the documented upstream maximum")
}

// A single row out of a large population is misleading rather than merely small, so
// none of these tools may inherit search_index's default of 1.
func TestProductDefaults_AreNotOne(t *testing.T) {
	for name, got := range map[string]int{
		"target-intel": defaultTargetIntelLimit,
		"ip-intel":     defaultIPIntelLimit,
		"canaries":     defaultCanaryLimit,
	} {
		assert.Greater(t, got, 1, "%s default limit must not be 1", name)
	}
}

func TestNewProductResponse_ReportsPopulationRatherThanRowCount(t *testing.T) {
	result := &client.IndexQueryResult{
		Data:  []json.RawMessage{json.RawMessage(`{"ip":"203.0.113.1"}`)},
		Total: 559290,
	}

	got := newProductResponse("target-intel", result)

	assert.Equal(t, "target-intel", got.Index, "the resolved index is reported back")
	assert.Equal(t, 1, got.Returned)
	assert.Equal(t, 559290, got.Total)
	assert.Contains(t, strings.Join(got.Notes, " "), "sample",
		"a partial result must say so, or it reads as the complete set")
}

func TestNewProductResponse_WarnsWhenTotalExceedsWhatPagingCanReach(t *testing.T) {
	beyond := newProductResponse("target-intel", &client.IndexQueryResult{
		Data:  []json.RawMessage{json.RawMessage(`{"ip":"203.0.113.1"}`)},
		Total: offsetCeiling + 1,
	})
	joined := strings.Join(beyond.Notes, " ")
	assert.Contains(t, joined, "backup",
		"beyond the paging ceiling the caller must be pointed at the backup")
	// The cheaper of the two routes, and the one a caller will not guess: cursor
	// pagination is not subject to the page x limit cap, so naming only the backup sends
	// callers to fetch a whole index when the tool they are holding can walk it.
	assert.Contains(t, joined, "start_cursor",
		"the cursor is a route past the ceiling and must be named alongside the backup")

	within := newProductResponse("target-intel", &client.IndexQueryResult{
		Data:  []json.RawMessage{json.RawMessage(`{"ip":"203.0.113.1"}`)},
		Total: 2,
	})
	assert.NotContains(t, strings.Join(within.Notes, " "), "backup",
		"a reachable result set must not be told to use a backup")
}

func TestNewProductResponse_NoNotesWhenEverythingWasReturned(t *testing.T) {
	got := newProductResponse("vulncheck-canaries-3d", &client.IndexQueryResult{
		Data:  []json.RawMessage{json.RawMessage(`{"src_ip":"198.51.100.7"}`)},
		Total: 1,
	})

	assert.Empty(t, got.Notes, "a complete answer needs no caveats")
}

func TestSearchTargetIntelHandler_MapsFiltersOntoUpstreamParameters(t *testing.T) {
	var got client.SearchIndexQuery
	yes := true
	handler := MakeSearchTargetIntelHandler(captureQuery(&got, nil))

	_, _, err := handler(context.Background(), nil, searchTargetIntelArgs{
		CVE:             "CVE-2024-21887",
		Vendor:          "ivanti",
		Product:         "connect secure",
		Version:         "22.3.0",
		CPE:             "cpe:2.3:a:ivanti:connect_secure:22.3.0:*:*:*:*:*:*:*",
		CIDR:            "203.0.113.0/24",
		Hostname:        "vpn.example.com",
		Domain:          "example.com",
		ASN:             "AS64500",
		Country:         "United States",
		CountryCode:     "US",
		Protocol:        "http",
		Transport:       "tcp",
		Port:            443,
		Classifications: "c2:cobalt-strike",
		ContainsCVE:     &yes,
		Limit:           25,
	})
	require.NoError(t, err)

	assert.Equal(t, targetIntelIndex, got.Index, "the tool owns its index; the caller never names one")
	assert.Equal(t, "CVE-2024-21887", got.CVE)
	assert.Equal(t, "ivanti", got.Vendor)
	assert.Equal(t, "connect secure", got.Product)
	assert.Equal(t, "22.3.0", got.Version)
	assert.Equal(t, "cpe:2.3:a:ivanti:connect_secure:22.3.0:*:*:*:*:*:*:*", got.CPE)
	assert.Equal(t, "203.0.113.0/24", got.CIDR)
	assert.Equal(t, "vpn.example.com", got.Hostname)
	assert.Equal(t, "example.com", got.Domain)
	assert.Equal(t, "AS64500", got.ASN)
	assert.Equal(t, "United States", got.Country)
	assert.Equal(t, "US", got.CountryCode)
	assert.Equal(t, "http", got.Protocol)
	assert.Equal(t, "tcp", got.Transport)
	assert.Equal(t, 443, got.Port)
	assert.Equal(t, "c2:cobalt-strike", got.Classifications)
	require.NotNil(t, got.ContainsCVE)
	assert.True(t, *got.ContainsCVE)
	assert.Equal(t, 25, got.Limit)
}

func TestSearchTargetIntelHandler_DefaultsLimitWithoutNamingAnIndex(t *testing.T) {
	var got client.SearchIndexQuery
	handler := MakeSearchTargetIntelHandler(captureQuery(&got, nil))

	_, _, err := handler(context.Background(), nil, searchTargetIntelArgs{CVE: "CVE-2021-36260"})
	require.NoError(t, err)

	assert.Equal(t, targetIntelIndex, got.Index)
	assert.Equal(t, defaultTargetIntelLimit, got.Limit)
}

// contains_cve=false means "hosts with no associated CVE", which is a real question,
// so it must reach the API rather than being treated as unset.
func TestSearchTargetIntelHandler_SendsContainsCVEFalse(t *testing.T) {
	var got client.SearchIndexQuery
	no := false
	handler := MakeSearchTargetIntelHandler(captureQuery(&got, nil))

	_, _, err := handler(context.Background(), nil, searchTargetIntelArgs{ContainsCVE: &no})
	require.NoError(t, err)

	require.NotNil(t, got.ContainsCVE)
	assert.False(t, *got.ContainsCVE)
}

func TestSearchTargetIntelHandler_OmitsContainsCVEWhenUnset(t *testing.T) {
	var got client.SearchIndexQuery
	handler := MakeSearchTargetIntelHandler(captureQuery(&got, nil))

	_, _, err := handler(context.Background(), nil, searchTargetIntelArgs{CVE: "CVE-2021-36260"})
	require.NoError(t, err)

	assert.Nil(t, got.ContainsCVE)
}

func TestSearchIPIntelHandler_ResolvesWindowAndMapsFilters(t *testing.T) {
	var got client.SearchIndexQuery
	handler := MakeSearchIPIntelHandler(captureQuery(&got, nil))

	_, _, err := handler(context.Background(), nil, searchIPIntelArgs{
		Window:      "30d",
		CVE:         "CVE-2024-24919",
		ID:          "initial-access",
		ASN:         "AS16509",
		CIDR:        "100.20.0.0/14",
		Country:     "Sweden",
		CountryCode: "SE",
		Hostname:    ".gov",
		ThreatActor: "UNC2630",
		Botnet:      "Fbot",
		Ransomware:  "Cactus",
		MitreID:     "G0013",
	})
	require.NoError(t, err)

	assert.Equal(t, "ipintel-30d", got.Index)
	assert.Equal(t, "CVE-2024-24919", got.CVE)
	assert.Equal(t, "initial-access", got.ID)
	assert.Equal(t, "AS16509", got.ASN)
	assert.Equal(t, "100.20.0.0/14", got.CIDR)
	assert.Equal(t, "Sweden", got.Country)
	assert.Equal(t, "SE", got.CountryCode)
	assert.Equal(t, ".gov", got.Hostname)
	assert.Equal(t, "UNC2630", got.ThreatActor)
	assert.Equal(t, "Fbot", got.Botnet)
	assert.Equal(t, "Cactus", got.Ransomware)
	assert.Equal(t, "G0013", got.MitreID)
	assert.Equal(t, defaultIPIntelLimit, got.Limit)
}

func TestSearchIPIntelHandler_RejectsAnUnknownWindowWithoutCallingTheAPI(t *testing.T) {
	called := false
	vc := &mockClient{
		searchIndexFn: func(_ context.Context, _ client.SearchIndexQuery) (*client.IndexQueryResult, error) {
			called = true
			return &client.IndexQueryResult{}, nil
		},
	}

	_, _, err := MakeSearchIPIntelHandler(vc)(context.Background(), nil, searchIPIntelArgs{Window: "7d"})

	require.Error(t, err)
	assert.False(t, called, "an invalid window must fail before a request is made")
}

func TestSearchCanariesHandler_ResolvesWindowAndMapsFilters(t *testing.T) {
	var got client.SearchIndexQuery
	handler := MakeSearchCanariesHandler(captureQuery(&got, nil))

	_, _, err := handler(context.Background(), nil, searchCanariesArgs{
		Window:     "all",
		CVE:        "CVE-2024-5276",
		Date:       "2025-10-17",
		SrcCountry: "IR",
		DstCountry: "US",
		SrcIP:      "198.51.100.7",
		SrcASN:     "AS12345",
		CIDR:       "1.0.0.0/24",
	})
	require.NoError(t, err)

	assert.Equal(t, "vulncheck-canaries", got.Index)
	assert.Equal(t, "CVE-2024-5276", got.CVE)
	assert.Equal(t, "2025-10-17", got.Date)
	assert.Equal(t, "IR", got.SrcCountry)
	assert.Equal(t, "US", got.DstCountry)
	assert.Equal(t, "198.51.100.7", got.SrcIP)
	assert.Equal(t, "AS12345", got.SrcASN)
	assert.Equal(t, "1.0.0.0/24", got.CIDR)
	assert.Equal(t, defaultCanaryLimit, got.Limit)
}

func TestProductHandlers_PropagateClientErrors(t *testing.T) {
	boom := errors.New("upstream exploded")
	vc := &mockClient{
		searchIndexFn: func(_ context.Context, _ client.SearchIndexQuery) (*client.IndexQueryResult, error) {
			return nil, boom
		},
	}

	_, _, err := MakeSearchTargetIntelHandler(vc)(context.Background(), nil, searchTargetIntelArgs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target intelligence")

	_, _, err = MakeSearchIPIntelHandler(vc)(context.Background(), nil, searchIPIntelArgs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IP intelligence")

	_, _, err = MakeSearchCanariesHandler(vc)(context.Background(), nil, searchCanariesArgs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "canary intelligence")
}

// The handler's job ends with a serialized payload, so check the envelope a client
// actually receives rather than only the struct the helper built.
func TestSearchTargetIntelHandler_SerializesTheProductEnvelope(t *testing.T) {
	var got client.SearchIndexQuery
	vc := captureQuery(&got, &client.IndexQueryResult{
		Data:       []json.RawMessage{json.RawMessage(`{"ip":"203.0.113.42","port":443}`)},
		Total:      559290,
		NextCursor: "abc123",
	})

	res, _, err := MakeSearchTargetIntelHandler(vc)(context.Background(), nil, searchTargetIntelArgs{CVE: "CVE-2021-36260"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Content, 1)

	text, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "product tools return their payload as text content")

	payload := decodeProduct(t, text.Text)
	assert.Equal(t, targetIntelIndex, payload.Index)
	assert.Equal(t, 559290, payload.Total)
	assert.Equal(t, 1, payload.Returned)
	assert.Equal(t, "abc123", payload.NextCursor)
	require.Len(t, payload.Data, 1)
	assert.JSONEq(t, `{"ip":"203.0.113.42","port":443}`, string(payload.Data[0]))
	assert.NotEmpty(t, payload.Notes, "one row out of 559290 must carry the sampling caveat")
}

// An empty page with a non-zero total is not an absence of data. The API applies
// its filter to a page after slicing it, so a small limit can legitimately return
// nothing while records match. Reporting that as a sample would tell the caller it
// had seen representative rows when it had seen none.
func TestNewProductResponse_DistinguishesAnEmptyPageFromNoData(t *testing.T) {
	t.Run("empty page with matches says so, and does not claim a sample", func(t *testing.T) {
		got := newProductResponse("target-intel", &client.IndexQueryResult{
			Data:  []json.RawMessage{},
			Total: 403,
		})

		assert.Zero(t, got.Returned)
		notes := strings.Join(got.Notes, " ")
		assert.Contains(t, notes, "retry with a larger limit",
			"an empty page with matches must tell the caller how to recover")
		assert.NotContains(t, notes, "these rows are a sample",
			"there are no rows, so calling them a sample is misleading")
	})

	t.Run("genuinely empty result stays quiet", func(t *testing.T) {
		got := newProductResponse("target-intel", &client.IndexQueryResult{
			Data:  []json.RawMessage{},
			Total: 0,
		})

		assert.Zero(t, got.Returned)
		assert.Empty(t, got.Notes, "no matches and no rows needs no explanation")
	})

	t.Run("partial page still reports as a sample", func(t *testing.T) {
		got := newProductResponse("target-intel", &client.IndexQueryResult{
			Data:  []json.RawMessage{json.RawMessage(`{"ip":"203.0.113.1"}`)},
			Total: 403,
		})

		assert.Equal(t, 1, got.Returned)
		assert.Contains(t, strings.Join(got.Notes, " "), "sample")
	})
}

// The classification filter takes either a classification or a product name, each on
// its own. A combined "type:product" value is accepted by the API but the suffix is
// ignored, so it returns the whole classification while looking like a narrower query
// — asking for one C2 framework and receiving every C2 host. The schema must not
// suggest that form, because there is no error to reveal it.
func TestSearchTargetIntelArgs_DoesNotSuggestCombinedClassifications(t *testing.T) {
	field, ok := reflect.TypeFor[searchTargetIntelArgs]().FieldByName("Classifications")
	require.True(t, ok)
	schema := field.Tag.Get("jsonschema")

	assert.Contains(t, schema, "the suffix is ignored",
		"the schema has to warn that the combined form does not narrow")
	assert.Contains(t, schema, "cobalt-strike",
		"a product name on its own is a real filter and worth naming")

	// The combined form may appear only as the thing being warned against, never as an
	// example to follow.
	if before, _, found := strings.Cut(schema, "c2:cobalt-strike"); found {
		assert.Contains(t, before, "Do not",
			"if the combined form is mentioned it must be as a warning")
	}
}

// TestIndexNotes pins which notes each shape of /v3/index result earns.
//
// The distinction that matters is between the universally-true half and the index-specific
// half: sending the specific half where it is false is worse than omitting it, because a
// caller told that `exploits` "describes a population of hosts or events" will read one row
// per CVE as a sample of hosts. The dropped-filter warning is not here — it travels in
// notes as its first entry, and TestDroppedFilterNote covers it.
func TestIndexNotes(t *testing.T) {
	rows := func(n int) []json.RawMessage {
		out := make([]json.RawMessage, n)
		for i := range out {
			out[i] = json.RawMessage(`{}`)
		}
		return out
	}

	tests := []struct {
		name     string
		index    string
		returned int
		tot      int
		cursor   string
		resumed  bool

		want     []string
		wantNone []string
	}{
		{
			name: "complete set earns nothing",
			// Every row matched is present, so there is nothing to warn about.
			index: "vulncheck-nvd2", returned: 5, tot: 5,
			wantNone: []string{partialSetNote, populationNote, emptyPageNote, ceilingNote},
		},
		{
			name: "empty page mid-walk points at the cursor, not a bigger limit",
			// Same diagnosis, different remedy: enlarging the limit is the wrong move
			// when the route onward is in the response the caller is already reading.
			index: "vulncheck-nvd2", returned: 0, tot: 40, cursor: "more", resumed: true,
			want:     []string{emptyPageMidWalkNote},
			wantNone: []string{emptyPageNote, partialSetNote, populationNote, cursorExhaustedNote},
		},
		{
			name: "an empty page mid-walk on a first call still gets the cursor advice",
			// start_cursor was passed but no page has been consumed yet; the cursor in
			// this response is still the route onward.
			index: "vulncheck-nvd2", returned: 0, tot: 40, cursor: "more", resumed: false,
			want:     []string{emptyPageMidWalkNote},
			wantNone: []string{emptyPageNote},
		},
		{
			name: "empty page at the end of a cursor walk says the walk is over",
			// The filter-after-slicing advice is wrong here: a larger limit cannot
			// help, because there is nothing left to page to.
			index: "vulncheck-nvd2", returned: 0, tot: 40, cursor: "", resumed: true,
			want:     []string{cursorExhaustedNote},
			wantNone: []string{emptyPageNote},
		},
		{
			name: "an empty page with no cursor in play keeps the retry advice",
			// A plain query returns an empty next_cursor too, so without
			// CursorContinuation this is indistinguishable from a finished walk.
			index: "vulncheck-nvd2", returned: 0, tot: 40, cursor: "", resumed: false,
			want:     []string{emptyPageNote},
			wantNone: []string{cursorExhaustedNote},
		},
		{
			name:  "a per-CVE index gets the universal half only",
			index: "vulncheck-nvd2", returned: 1, tot: 400,
			want:     []string{partialSetNote},
			wantNone: []string{populationNote},
		},
		{
			name:  "a host index gets both halves",
			index: "target-intel", returned: 10, tot: 9_000,
			want: []string{partialSetNote, populationNote},
		},
		{
			name:  "windowed families match by prefix",
			index: "ipintel-30d", returned: 10, tot: 9_000,
			want: []string{partialSetNote, populationNote},
		},
		{
			name: "canaries match by prefix, including the unwindowed index",
			// canaryIndex("all") resolves to the bare prefix, so this is the name the
			// tool actually queries — "vulncheck-canaries-all" is not an index.
			index: "vulncheck-canaries", returned: 20, tot: 9_000,
			want: []string{partialSetNote, populationNote},
		},
		{
			name: "exploits is one row per CVE, not a population",
			// It sits in dedicatedTools alongside the host indices, which is why
			// gating on that map would tell this caller something false.
			index: "exploits", returned: 25, tot: 900,
			want:     []string{partialSetNote},
			wantNone: []string{populationNote},
		},
		{
			name:  "a total beyond the offset ceiling names both routes",
			index: "vulncheck-nvd2", returned: 1, tot: offsetCeiling + 1,
			want: []string{partialSetNote, ceilingNote},
		},
		{
			name: "the ceiling note is not repeated to a caller already walking",
			// It tells the caller to use the cursor they are holding, on every page.
			index: "vulncheck-nvd2", returned: 1, tot: offsetCeiling + 1,
			cursor: "more", resumed: true,
			want:     []string{partialSetNote},
			wantNone: []string{ceilingNote},
		},
		{
			name: "a partial set names the route to the rest",
			// Saying "report 5194" without saying how to reach the other 5192 is half
			// an answer, and this tool takes start_cursor.
			index: "vulncheck-nvd2", returned: 2, tot: 5_194,
			want: []string{partialSetNote, cursorRouteNote},
		},
		{
			name:  "the route is not repeated to a caller already walking",
			index: "vulncheck-nvd2", returned: 2, tot: 5_194, cursor: "more", resumed: true,
			want:     []string{partialSetNote},
			wantNone: []string{cursorRouteNote},
		},
		{
			name:  "above the ceiling, ceilingNote names both routes instead",
			index: "vulncheck-nvd2", returned: 1, tot: offsetCeiling + 1,
			want:     []string{partialSetNote, ceilingNote},
			wantNone: []string{cursorRouteNote},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notes := indexNotes(tt.index, &client.IndexQueryResult{
				Data:               rows(tt.returned),
				Total:              tt.tot,
				NextCursor:         tt.cursor,
				CursorContinuation: tt.resumed,
			})
			for _, want := range tt.want {
				assert.Contains(t, notes, want)
			}
			for _, unwanted := range tt.wantNone {
				assert.NotContains(t, notes, unwanted)
			}
		})
	}
}

// TestDroppedFilterNote covers the one note that says the answer is wrong rather than
// partial: a filter the index does not accept, which the API discards while returning
// HTTP 200 and an unfiltered total.
func TestDroppedFilterNote(t *testing.T) {
	tests := []struct {
		name     string
		sent     []string
		accepted []string
		want     []string
		wantNone bool
	}{
		{
			name: "an accepted filter draws no complaint",
			sent: []string{"cve"}, accepted: []string{"cve", "threat_actor"},
			wantNone: true,
		},
		{
			name: "a filter the index does not accept is named",
			// The real case: target-intel accepts neither threat_actor nor
			// ransomware, and answers 200 with the whole index.
			sent: []string{"cve", "threat_actor"}, accepted: []string{"asn", "country", "cve"},
			want: []string{"FILTERS NOT APPLIED", "threat_actor"},
		},
		{
			name: "several dropped filters are all named",
			sent: []string{"botnet", "ransomware"}, accepted: []string{"cve"},
			want: []string{"botnet, ransomware"},
		},
		{
			name: "no published parameter list means no claim either way",
			// Some indices omit the list on a zero-row response. An absent list is
			// "unknown", not "accepts nothing" — asserting a drop here would fire on
			// a genuine no-match.
			sent: []string{"cve", "threat_actor"}, accepted: nil,
			wantNone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note := droppedFilterNoteFor(&client.IndexQueryResult{
				FiltersSent:     tt.sent,
				FiltersAccepted: tt.accepted,
			})
			if tt.wantNone {
				assert.Empty(t, note)
				return
			}
			for _, want := range tt.want {
				assert.Contains(t, note, want)
			}
		})
	}
}
