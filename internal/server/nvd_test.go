package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

// nvdPayload is the envelope every search_nvd_* tool returns, with the rows left raw.
type nvdPayload struct {
	Data       []map[string]any `json:"data"`
	Returned   int              `json:"returned"`
	Total      int              `json:"total"`
	NextCursor string           `json:"next_cursor"`
	Notes      []string         `json:"notes"`
}

func decodeNVDPayload(t *testing.T, text string) nvdPayload {
	t.Helper()
	var got nvdPayload
	require.NoError(t, json.Unmarshal([]byte(text), &got))
	return got
}

func TestNVDLimit(t *testing.T) {
	assert.Equal(t, int32(5), nvdLimit(0, 5, 20), "unset takes the default")
	assert.Equal(t, int32(5), nvdLimit(-3, 5, 20), "negative takes the default")
	assert.Equal(t, int32(12), nvdLimit(12, 5, 20))
	assert.Equal(t, int32(20), nvdLimit(500, 5, 20), "clamped to the ceiling")
}

// TestNVDCursorEnvelope pins the same gate search_cve has on cursorRouteNote: the last page
// of a walk carries no next_cursor, like a first page that never asked for one, and a caller
// holding it must not be sent back to start the walk again.
func TestNVDCursorEnvelope(t *testing.T) {
	tests := []struct {
		name       string
		returned   int
		total      int
		nextCursor string
		cursorArg  string
		wantNotes  []string
	}{
		{name: "complete answer: no notes", returned: 3, total: 3},
		{name: "partial, no walk: name the route", returned: 5, total: 71, wantNotes: []string{partialSetNote, cursorRouteNote}},
		{name: "partial, walk under way", returned: 5, total: 71, nextCursor: "next", cursorArg: "prev", wantNotes: []string{partialSetNote}},
		{name: "partial, last page of a walk", returned: 1, total: 71, cursorArg: "prev", wantNotes: []string{partialSetNote}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := nvdCursorEnvelope(tt.returned, tt.total, tt.nextCursor, tt.cursorArg)
			assert.Equal(t, tt.returned, env.Returned)
			assert.Equal(t, tt.total, env.Total)
			assert.Equal(t, tt.nextCursor, env.NextCursor)
			assert.Equal(t, tt.wantNotes, env.Notes)
		})
	}
}

func TestMakeSearchNVDCVEsHandler(t *testing.T) {
	id := "CVE-2021-44228"

	t.Run("maps arguments and applies the default page size", func(t *testing.T) {
		var got client.NVDCVEsQuery
		mock := &mockClient{
			searchNVDCVEsFn: func(_ context.Context, q client.NVDCVEsQuery) (*client.NVDResult[vulncheck.NvdcvesNvdCveExtended], error) {
				got = q
				return &client.NVDResult[vulncheck.NvdcvesNvdCveExtended]{
					Data: []vulncheck.NvdcvesNvdCveExtended{{Id: &id}}, Total: 1,
				}, nil
			},
		}

		result := runTool(t, mock, func(vc client.Client) toolCall {
			return call(MakeSearchNVDCVEsHandler(vc), searchNVDCVEsArgs{
				CVEID: id, HasKEV: true, LastModStartDate: "2026-01-01T00:00:00.000", LastModEndDate: "2026-02-01T00:00:00.000",
			})
		})

		assert.Equal(t, client.NVDCVEsQuery{
			CVEID: id, HasKEV: true, LastModStartDate: "2026-01-01T00:00:00.000", LastModEndDate: "2026-02-01T00:00:00.000",
			Page: client.NVDPage{Limit: 5},
		}, got)

		payload := decodeNVDPayload(t, payloadText(t, result))
		require.Len(t, payload.Data, 1)
		assert.Equal(t, id, payload.Data[0]["id"], "records sit directly under data, not under NVD's cve wrapper")
		assert.Equal(t, 1, payload.Returned)
		assert.Empty(t, payload.Notes)
	})

	t.Run("clamps the page size and passes the cursor through", func(t *testing.T) {
		var got client.NVDCVEsQuery
		mock := &mockClient{
			searchNVDCVEsFn: func(_ context.Context, q client.NVDCVEsQuery) (*client.NVDResult[vulncheck.NvdcvesNvdCveExtended], error) {
				got = q
				return &client.NVDResult[vulncheck.NvdcvesNvdCveExtended]{Data: []vulncheck.NvdcvesNvdCveExtended{}}, nil
			},
		}
		runTool(t, mock, func(vc client.Client) toolCall {
			return call(MakeSearchNVDCVEsHandler(vc), searchNVDCVEsArgs{CVETag: "disputed", Limit: 500, Cursor: "tok"})
		})
		assert.Equal(t, client.NVDPage{Limit: 20, Cursor: "tok"}, got.Page)
	})

	t.Run("a partial page says so and names the cursor route", func(t *testing.T) {
		mock := &mockClient{
			searchNVDCVEsFn: func(context.Context, client.NVDCVEsQuery) (*client.NVDResult[vulncheck.NvdcvesNvdCveExtended], error) {
				return &client.NVDResult[vulncheck.NvdcvesNvdCveExtended]{
					Data: make([]vulncheck.NvdcvesNvdCveExtended, 5), Total: 837,
				}, nil
			},
		}
		result := runTool(t, mock, func(vc client.Client) toolCall {
			return call(MakeSearchNVDCVEsHandler(vc), searchNVDCVEsArgs{CVETag: "disputed"})
		})
		payload := decodeNVDPayload(t, payloadText(t, result))
		assert.Equal(t, 837, payload.Total)
		assert.Equal(t, []string{partialSetNote, cursorRouteNote}, payload.Notes)
	})

	t.Run("a client error propagates", func(t *testing.T) {
		mock := &mockClient{
			searchNVDCVEsFn: func(context.Context, client.NVDCVEsQuery) (*client.NVDResult[vulncheck.NvdcvesNvdCveExtended], error) {
				return nil, errors.New("searching NVD CVEs: 400 Bad Request: date range exceeds 120 days")
			},
		}
		_, _, err := MakeSearchNVDCVEsHandler(mock)(context.Background(), nil, searchNVDCVEsArgs{})
		assert.ErrorContains(t, err, "date range exceeds 120 days")
	})
}

func TestMakeSearchNVDCVEHistoryHandler(t *testing.T) {
	var got client.NVDCVEHistoryQuery
	cveID, event := "CVE-2021-44228", "CVE Modified"
	mock := &mockClient{
		searchNVDCVEHistoryFn: func(_ context.Context, q client.NVDCVEHistoryQuery) (*client.NVDResult[vulncheck.RestNvdChange], error) {
			got = q
			return &client.NVDResult[vulncheck.RestNvdChange]{
				Data: []vulncheck.RestNvdChange{{CveId: &cveID, EventName: &event}}, Total: 71, NextCursor: "next",
			}, nil
		},
	}

	result := runTool(t, mock, func(vc client.Client) toolCall {
		return call(MakeSearchNVDCVEHistoryHandler(vc), searchNVDCVEHistoryArgs{CVEID: cveID, StartCursor: true})
	})

	assert.Equal(t, client.NVDCVEHistoryQuery{CVEID: cveID, Page: client.NVDPage{Limit: 10, StartCursor: true}}, got)
	payload := decodeNVDPayload(t, payloadText(t, result))
	assert.Equal(t, cveID, payload.Data[0]["cveId"])
	assert.Equal(t, "next", payload.NextCursor)
	assert.Equal(t, []string{partialSetNote}, payload.Notes, "a cursor came back, so the route needs no explaining")
}

func TestMakeSearchNVDCPEsHandler(t *testing.T) {
	var got client.NVDCPEsQuery
	name := "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
	mock := &mockClient{
		searchNVDCPEsFn: func(_ context.Context, q client.NVDCPEsQuery) (*client.NVDResult[vulncheck.NvdcpesNvdCpe], error) {
			got = q
			return &client.NVDResult[vulncheck.NvdcpesNvdCpe]{
				Data: []vulncheck.NvdcpesNvdCpe{{CpeName: &name}}, Total: 1,
			}, nil
		},
	}

	result := runTool(t, mock, func(vc client.Client) toolCall {
		return call(MakeSearchNVDCPEsHandler(vc), searchNVDCPEsArgs{CPEMatchString: "cpe:2.3:a:apache:log4j", Limit: 1000})
	})

	assert.Equal(t, client.NVDCPEsQuery{CPEMatchString: "cpe:2.3:a:apache:log4j", Page: client.NVDPage{Limit: 100}}, got)
	assert.Equal(t, name, decodeNVDPayload(t, payloadText(t, result)).Data[0]["cpeName"])
}

func TestMakeSearchNVDCPEMatchHandler(t *testing.T) {
	var got client.NVDCPEMatchQuery
	id := "mc-1"
	mock := &mockClient{
		searchNVDCPEMatchFn: func(_ context.Context, q client.NVDCPEMatchQuery) (*client.NVDResult[vulncheck.NvdcpematchNvdMatchString], error) {
			got = q
			return &client.NVDResult[vulncheck.NvdcpematchNvdMatchString]{
				Data: []vulncheck.NvdcpematchNvdMatchString{{MatchCriteriaId: &id}}, Total: 1,
			}, nil
		},
	}

	result := runTool(t, mock, func(vc client.Client) toolCall {
		return call(MakeSearchNVDCPEMatchHandler(vc), searchNVDCPEMatchArgs{CVEID: "CVE-2021-44228"})
	})

	assert.Equal(t, client.NVDCPEMatchQuery{CVEID: "CVE-2021-44228", Page: client.NVDPage{Limit: 10}}, got)
	assert.Equal(t, id, decodeNVDPayload(t, payloadText(t, result)).Data[0]["matchCriteriaId"])
}

func TestMakeSearchNVDSourcesHandler(t *testing.T) {
	sources := func(n int) []vulncheck.NvdsourceNvdSource {
		rows := make([]vulncheck.NvdsourceNvdSource, n)
		for i := range rows {
			rows[i] = vulncheck.NvdsourceNvdSource{SourceIdentifiers: []string{"cve@mitre.org"}}
		}
		return rows
	}

	tests := []struct {
		name      string
		args      searchNVDSourcesArgs
		rows      int
		total     int
		wantPage  client.NVDPage
		wantNotes []string
	}{
		{
			name: "first page of many names the start_index route", args: searchNVDSourcesArgs{},
			rows: 20, total: 514, wantPage: client.NVDPage{Limit: 20},
			wantNotes: []string{partialSetNote, nvdStartIndexRouteNote},
		},
		{
			name: "last page carries no route", args: searchNVDSourcesArgs{StartIndex: 500},
			rows: 14, total: 514, wantPage: client.NVDPage{Limit: 20, StartIndex: 500},
		},
		{
			name: "a single source is the whole answer", args: searchNVDSourcesArgs{SourceIdentifier: "cve@mitre.org"},
			rows: 1, total: 1, wantPage: client.NVDPage{Limit: 20},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got client.NVDSourcesQuery
			mock := &mockClient{
				searchNVDSourcesFn: func(_ context.Context, q client.NVDSourcesQuery) (*client.NVDResult[vulncheck.NvdsourceNvdSource], error) {
					got = q
					return &client.NVDResult[vulncheck.NvdsourceNvdSource]{Data: sources(tt.rows), Total: tt.total}, nil
				},
			}
			result := runTool(t, mock, func(vc client.Client) toolCall {
				return call(MakeSearchNVDSourcesHandler(vc), tt.args)
			})

			assert.Equal(t, tt.wantPage, got.Page)
			payload := decodeNVDPayload(t, payloadText(t, result))
			assert.Equal(t, tt.total, payload.Total)
			assert.Empty(t, payload.NextCursor, "/source/2.0 has no cursor")
			assert.Equal(t, tt.wantNotes, payload.Notes)
		})
	}
}

// TestRowName_NVDRecords pins the identifiers the response cap reports for NVD rows it
// withholds: each is one the caller can fetch the row by afterwards.
func TestRowName_NVDRecords(t *testing.T) {
	assert.Equal(t, "CVE-2021-44228", rowName(map[string]any{"id": "CVE-2021-44228", "sourceIdentifier": "nvd@nist.gov"}))
	// A history row has no identifier the API can fetch it by, and every row of one CVE's
	// history shares its cveId, so naming rows by it would list one CVE once per row withheld.
	assert.Empty(t, rowName(map[string]any{"cveId": "CVE-2021-44228", "cveChangeId": "x", "eventName": "CVE Modified"}))
	assert.Equal(t, "mc-1", rowName(map[string]any{"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "matchCriteriaId": "mc-1"}))
	assert.Equal(t, "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", rowName(map[string]any{"cpeName": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "cpeNameId": "uuid"}))
}
