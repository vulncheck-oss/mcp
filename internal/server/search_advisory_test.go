package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// advisoryRef builds a result row identified by CVE ID, optionally naming the
// products it affects. Rows are raw JSON, matching what the API returns and what
// the handler passes through.
func advisoryRef(cve string, products ...string) json.RawMessage {
	record := map[string]any{}
	if cve != "" {
		record["cveMetadata"] = map[string]any{"cveId": cve}
	}
	if len(products) > 0 {
		affected := make([]map[string]any, 0, len(products))
		for _, p := range products {
			affected = append(affected, map[string]any{"product": p})
		}
		record["containers"] = map[string]any{"cna": map[string]any{"affected": affected}}
	}
	raw, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return raw
}

// advisoryRefWithSource builds a row carrying the double-encoded `source` value
// that the generated SDK types cannot decode: a JSON string wrapping a JSON object.
func advisoryRefWithSource(cve string) json.RawMessage {
	raw, err := json.Marshal(map[string]any{
		"cveMetadata": map[string]any{"cveId": cve},
		"containers": map[string]any{
			"cna": map[string]any{
				"source": `{"advisory":"GHSA-w5fx-fh39-j5rw","discovery":"UNKNOWN"}`,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func advisoryResult(total int32, refs ...json.RawMessage) *client.SearchAdvisoryResult {
	if refs == nil {
		refs = []json.RawMessage{}
	}
	return &client.SearchAdvisoryResult{Data: refs, Total: total}
}

// cveIDs reads the CVE IDs out of a response's rows.
func cveIDs(t *testing.T, data []json.RawMessage) []string {
	t.Helper()
	ids := make([]string, 0, len(data))
	for _, raw := range data {
		var record struct {
			CveMetadata struct {
				CveID string `json:"cveId"`
			} `json:"cveMetadata"`
		}
		require.NoError(t, json.Unmarshal(raw, &record))
		ids = append(ids, record.CveMetadata.CveID)
	}
	return ids
}

// runAdvisoryHandler invokes the handler against a mock that answers from respond
// and records every query it was asked, so a test can assert the fan-out.
func runAdvisoryHandler(
	t *testing.T,
	args searchAdvisoryArgs,
	respond func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error),
) (searchAdvisoryResponse, []client.SearchAdvisoryQuery, error) {
	t.Helper()

	var queries []client.SearchAdvisoryQuery
	mock := &mockClient{
		searchAdvisoryFn: func(_ context.Context, q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
			queries = append(queries, q)
			return respond(q)
		},
	}

	result, _, err := MakeSearchAdvisoryHandler(mock)(context.Background(), nil, args)
	if err != nil {
		return searchAdvisoryResponse{}, queries, err
	}

	var got searchAdvisoryResponse
	text := result.Content[0].(*mcp.TextContent).Text
	require.NoError(t, json.Unmarshal([]byte(text), &got))
	return got, queries, nil
}

func runAdvisoryResult(
	t *testing.T,
	args searchAdvisoryArgs,
	respond func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error),
) (*mcp.CallToolResult, []client.SearchAdvisoryQuery, error) {
	t.Helper()

	var queries []client.SearchAdvisoryQuery
	mock := &mockClient{
		searchAdvisoryFn: func(_ context.Context, q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
			queries = append(queries, q)
			return respond(q)
		},
	}

	result, _, err := MakeSearchAdvisoryHandler(mock)(context.Background(), nil, args)
	return result, queries, err
}

func TestMakeSearchAdvisoryHandler(t *testing.T) {
	tests := []struct {
		name       string
		args       searchAdvisoryArgs
		clientResp *client.SearchAdvisoryResult
		clientErr  error
		wantErr    bool
		wantLimit  int32
		wantTotal  int32
		wantLen    int
	}{
		{
			name:       "returns advisory results",
			args:       searchAdvisoryArgs{Name: "vulncheck", CveID: "CVE-2024-1234", Limit: 5},
			clientResp: advisoryResult(1, advisoryRef("CVE-2024-1234")),
			wantLimit:  5,
			wantTotal:  1,
			wantLen:    1,
		},
		{
			name:       "zero limit defaults to ten",
			args:       searchAdvisoryArgs{Name: "vulncheck"},
			clientResp: advisoryResult(0),
			wantLimit:  defaultAdvisoryLimit,
		},
		{
			name:       "limit is clamped to the upstream maximum",
			args:       searchAdvisoryArgs{Name: "vulncheck", Limit: 500},
			clientResp: advisoryResult(0),
			wantLimit:  maxAdvisoryLimit,
		},
		{
			name:      "client error propagates",
			args:      searchAdvisoryArgs{Name: "vulncheck"},
			clientErr: errors.New("api error"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, queries, err := runAdvisoryHandler(t, tt.args,
				func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
					return tt.clientResp, tt.clientErr
				})

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, queries)

			assert.Equal(t, tt.args.Name, queries[0].Name)
			assert.Equal(t, tt.args.CveID, queries[0].CveID)
			assert.Equal(t, tt.wantLimit, queries[0].Limit)
			assert.Equal(t, tt.wantTotal, got.Total)
			assert.Len(t, got.Data, tt.wantLen)
		})
	}
}

// TestSearchAdvisoryNoWidening covers the paths that must keep issuing exactly one
// upstream call and returning the wire shape callers already depend on.
func TestSearchAdvisoryNoWidening(t *testing.T) {
	t.Run("a complete result is not widened", func(t *testing.T) {
		got, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropics"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(2, advisoryRef("CVE-1"), advisoryRef("CVE-2")), nil
			})

		require.NoError(t, err)
		assert.Len(t, queries, 1, "total equals the rows returned, so nothing was discarded")
		assert.Empty(t, got.VendorsTried)
		assert.Empty(t, got.Notes)
	})

	t.Run("a cursor is passed through without widening", func(t *testing.T) {
		_, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Cursor: "abc"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25), nil
			})

		require.NoError(t, err)
		assert.Len(t, queries, 1, "a cursor addresses one query's page and cannot be replayed")
	})

	t.Run("no vendor means nothing to vary", func(t *testing.T) {
		_, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{CveID: "CVE-2024-1234"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(9), nil
			})

		require.NoError(t, err)
		assert.Len(t, queries, 1)
	})
}

func TestSearchAdvisoryVendorFanOut(t *testing.T) {
	t.Run("recovers rows filed under another capitalisation", func(t *testing.T) {
		got, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				if q.Vendor == "Anthropic" {
					return advisoryResult(25, advisoryRef("CVE-2026-22561")), nil
				}
				return advisoryResult(25, advisoryRef("CVE-2026-33068")), nil
			})

		require.NoError(t, err)
		assert.Equal(t, []string{"anthropic", "Anthropic"}, got.VendorsTried)
		assert.Equal(t, []string{"CVE-2026-33068", "CVE-2026-22561"}, cveIDs(t, got.Data),
			"union preserves first-seen order")

		assert.Equal(t, "anthropic", queries[0].Vendor)
		assert.Equal(t, "Anthropic", queries[len(queries)-1].Vendor)
		assert.Contains(t, got.Notes, widenedNote)
	})

	// The upstream filter runs on one page and that page's ordering is unstable, so
	// a limit below the reported total yields a different sample per call. The
	// handler must widen the page to cover the whole match set.
	t.Run("the page is widened to cover the reported total", func(t *testing.T) {
		_, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Limit: 10},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25, advisoryRef("CVE-1")), nil
			})

		require.NoError(t, err)
		require.Greater(t, len(queries), 1)
		assert.Equal(t, int32(10), queries[0].Limit, "the first call honours the caller")
		for _, q := range queries[1:] {
			assert.Equal(t, int32(25), q.Limit, "widened calls cover the reported total")
		}
	})

	t.Run("the covering limit is capped at the upstream maximum", func(t *testing.T) {
		_, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "linux"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(10536, advisoryRef("CVE-1")), nil
			})

		require.NoError(t, err)
		for _, q := range queries[1:] {
			assert.Equal(t, int32(maxAdvisoryLimit), q.Limit)
		}
	})

	t.Run("no re-query when the limit already covers the total", func(t *testing.T) {
		_, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Limit: 100},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25), nil
			})

		require.NoError(t, err)
		assert.Len(t, queries, 2, "one call per spelling, with no redundant repeat")
	})

	t.Run("an all-caps vendor tries three spellings", func(t *testing.T) {
		got, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "ANTHROPIC", Limit: 100},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25), nil
			})

		require.NoError(t, err)
		assert.Equal(t, []string{"ANTHROPIC", "anthropic", "Anthropic"}, got.VendorsTried)
		assert.Len(t, queries, maxVendorVariants, "one call per spelling")
	})

	t.Run("the same CVE from two spellings is returned once", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25, advisoryRef("CVE-DUPE")), nil
			})

		require.NoError(t, err)
		assert.Len(t, got.Data, 1)
	})

	t.Run("rows without a CVE ID are kept rather than collapsed", func(t *testing.T) {
		got, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25, advisoryRef(""), advisoryRef("")), nil
			})

		require.NoError(t, err)
		assert.Len(t, got.Data, 2*len(queries),
			"unidentifiable rows cannot be de-duplicated, so every call's rows are kept")
	})

	t.Run("a failing variant does not lose the rows already found", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				if q.Vendor == "Anthropic" {
					return nil, errors.New("upstream 500")
				}
				return advisoryResult(25, advisoryRef("CVE-KEPT")), nil
			})

		require.NoError(t, err)
		assert.Len(t, got.Data, 1)
	})

	t.Run("a failing variant is reported, not swallowed", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				if q.Vendor == "Anthropic" {
					return nil, errors.New("json: cannot unmarshal string into Go struct field")
				}
				return advisoryResult(25, advisoryRef("CVE-KEPT")), nil
			})

		require.NoError(t, err)
		assert.Equal(t, []string{"Anthropic"}, got.VendorsFailed,
			"an upstream failure must not look like a spelling with no advisories")
		assert.Contains(t, got.Notes, variantFailedNote)
	})

	t.Run("a widened response drops next_cursor", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return &client.SearchAdvisoryResult{
					Data:       []json.RawMessage{advisoryRef("CVE-1")},
					Total:      25,
					NextCursor: "cursor-abc",
				}, nil
			})

		require.NoError(t, err)
		assert.Empty(t, got.NextCursor, "a cursor cannot paginate a union of spellings")
	})

	t.Run("total exceeding the rows returned is explained", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(25, advisoryRef("CVE-1")), nil
			})

		require.NoError(t, err)
		assert.Contains(t, got.Notes, totalMismatchNote)
		assert.Contains(t, got.Notes, slugNote)
	})
}

func TestSearchAdvisoryProductFallback(t *testing.T) {
	t.Run("an unmatchable product is dropped and real products listed", func(t *testing.T) {
		got, queries, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Product: "claude"},
			func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				if q.Product != "" {
					return advisoryResult(0), nil
				}
				return advisoryResult(25, advisoryRef("CVE-2026-22561", "Claude Desktop - Windows")), nil
			})

		require.NoError(t, err)
		assert.Contains(t, got.Notes, productDroppedNote)
		assert.Equal(t, []string{"Claude Desktop - Windows"}, got.ProductsFound)
		require.NotEmpty(t, got.Data)

		for _, q := range queries[len(queries)-2:] {
			assert.Empty(t, q.Product, "the retry drops the product filter")
			assert.Equal(t, int32(maxAdvisoryLimit), q.Limit,
				"the widened match set needs the largest page the API allows")
		}
	})

	t.Run("a product that does match is left alone", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Product: "Claude Desktop - Windows"},
			func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				require.NotEmpty(t, q.Product)
				return advisoryResult(25, advisoryRef("CVE-2026-22561")), nil
			})

		require.NoError(t, err)
		assert.NotContains(t, got.Notes, productDroppedNote)
	})
}

// TestSearchAdvisoryResponseSize covers the byte bound. `limit` caps the number of
// rows but not their size — a single vendor=linux advisory is ~700 KB, and before
// this bound the same query returned 6.2 MB.
func TestSearchAdvisoryResponseSize(t *testing.T) {
	// bulkyRef builds a row whose serialized size is dominated by one long field.
	bulkyRef := func(cve string, padding int) json.RawMessage {
		raw, err := json.Marshal(map[string]any{
			"cveMetadata": map[string]any{"cveId": cve},
			"containers": map[string]any{
				"cna": map[string]any{"title": strings.Repeat("x", padding)},
			},
		})
		require.NoError(t, err)
		return raw
	}

	t.Run("an oversized row is reported, not silently lost", func(t *testing.T) {
		result, _, err := runAdvisoryResult(t,
			searchAdvisoryArgs{Vendor: "linux"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(10,
					bulkyRef("CVE-HUGE-1", 4*defaultResponseBudget),
					bulkyRef("CVE-HUGE-2", 4*defaultResponseBudget),
				), nil
			})
		require.NoError(t, err)

		report := sizeReport(t, result)
		require.NotNil(t, report, "an oversized response must say so")
		assert.NotEmpty(t, report.Note)
		// These rows are bulky because of a long string, not a long array, so no array
		// limit can shrink them and the floor is reached.
		require.NotNil(t, report.Outline, "shape and weight, rather than an empty answer")
		assert.Positive(t, report.Outline.Bytes)
	})

	t.Run("a small row behind an oversized one is still returned", func(t *testing.T) {
		result, _, err := runAdvisoryResult(t,
			searchAdvisoryArgs{Vendor: "linux"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(10,
					bulkyRef("CVE-HUGE", 4*defaultResponseBudget),
					advisoryRef("CVE-SMALL"),
				), nil
			})
		require.NoError(t, err)

		var got searchAdvisoryResponse
		require.NoError(t, json.Unmarshal([]byte(payloadText(t, result)), &got))
		require.Len(t, got.Data, 1, "an oversized row must not hide the rows behind it")
		assert.Equal(t, []string{"CVE-SMALL"}, cveIDs(t, got.Data))

		report := sizeReport(t, result)
		require.NotNil(t, report)
		assert.Contains(t, report.RemovedIDs["/data"], "CVE-HUGE",
			"the row that did not fit is named so it can be fetched by cve_id")
	})

	t.Run("responses stay within the byte bound", func(t *testing.T) {
		var refs []json.RawMessage
		for i := range 40 {
			refs = append(refs, bulkyRef(fmt.Sprintf("CVE-%d", i), 20_000))
		}

		mock := &mockClient{
			searchAdvisoryFn: func(_ context.Context, _ client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(500, refs...), nil
			},
		}
		result, _, err := MakeSearchAdvisoryHandler(mock)(
			context.Background(), nil, searchAdvisoryArgs{Vendor: "linux"})
		require.NoError(t, err)

		assert.LessOrEqual(t, len(payloadText(t, result)), defaultResponseBudget,
			"the serialized response must stay within the budget")
	})

	t.Run("a small result is untouched", func(t *testing.T) {
		result, _, err := runAdvisoryResult(t,
			searchAdvisoryArgs{Vendor: "anthropics"},
			func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
				return advisoryResult(1, advisoryRef("CVE-1")), nil
			})

		require.NoError(t, err)
		assert.Nil(t, sizeReport(t, result), "nothing was done to it, so nothing is reported")
	})
}

// TestSearchAdvisoryLimitContract covers what `limit` means to a caller: at most
// that many rows come back. Widening reads larger upstream pages than requested,
// because the API's exact filter only ever sees one page, but that is a transport
// detail and must not leak into the row count.
func TestSearchAdvisoryLimitContract(t *testing.T) {
	// respond gives each spelling four distinct rows, so a union of 8 exists.
	respond := func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
		prefix := "lower"
		if q.Vendor == "Anthropic" {
			prefix = "upper"
		}
		refs := make([]json.RawMessage, 0, 4)
		for i := range 4 {
			refs = append(refs, advisoryRef(fmt.Sprintf("CVE-%s-%d", prefix, i)))
		}
		return advisoryResult(25, refs...), nil
	}

	for _, limit := range []int32{1, 2, 5, 8} {
		t.Run(fmt.Sprintf("limit %d is honoured", limit), func(t *testing.T) {
			got, _, err := runAdvisoryHandler(t,
				searchAdvisoryArgs{Vendor: "anthropic", Limit: limit}, respond)

			require.NoError(t, err)
			assert.LessOrEqual(t, len(got.Data), int(limit),
				"a caller asking for N rows must not receive more")
			assert.Equal(t, len(got.Data), got.Returned)
		})
	}

	t.Run("trimming is disclosed, not silent", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Limit: 2}, respond)

		require.NoError(t, err)
		assert.Contains(t, got.Notes, trimmedNote,
			"records were found and withheld, so total exceeding returned is real loss here")
	})

	t.Run("no trim note when everything found is returned", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Limit: 100}, respond)

		require.NoError(t, err)
		assert.NotContains(t, got.Notes, trimmedNote)
	})

	t.Run("a small limit still samples every spelling", func(t *testing.T) {
		got, _, err := runAdvisoryHandler(t,
			searchAdvisoryArgs{Vendor: "anthropic", Limit: 2}, respond)

		require.NoError(t, err)
		ids := cveIDs(t, got.Data)
		require.Len(t, ids, 2)

		var sawLower, sawUpper bool
		for _, id := range ids {
			sawLower = sawLower || strings.Contains(id, "lower")
			sawUpper = sawUpper || strings.Contains(id, "upper")
		}
		assert.True(t, sawLower && sawUpper,
			"rows are interleaved, so trimming cannot discard a whole spelling: got %v", ids)
	})
}

// TestSearchAdvisoryRawPassthrough guards the reason records are carried as raw
// JSON: the API double-encodes containers.*.source and
// containers.*.metrics[].other.content as JSON strings wrapping JSON objects, which
// the generated SDK types reject. Raw passthrough must survive that untouched.
func TestSearchAdvisoryRawPassthrough(t *testing.T) {
	got, _, err := runAdvisoryHandler(t,
		searchAdvisoryArgs{Vendor: "anthropics"},
		func(client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
			return advisoryResult(1, advisoryRefWithSource("CVE-2025-59532")), nil
		})

	require.NoError(t, err, "a record the SDK types cannot decode must still be returned")
	require.Len(t, got.Data, 1)
	assert.Equal(t, []string{"CVE-2025-59532"}, cveIDs(t, got.Data),
		"identity is still readable for de-duplication")

	var record struct {
		Containers struct {
			Cna struct {
				Source string `json:"source"`
			} `json:"cna"`
		} `json:"containers"`
	}
	require.NoError(t, json.Unmarshal(got.Data[0], &record))
	assert.JSONEq(t,
		`{"advisory":"GHSA-w5fx-fh39-j5rw","discovery":"UNKNOWN"}`,
		record.Containers.Cna.Source,
		"the double-encoded value reaches the model byte-for-byte, unrepaired")
}

// TestSearchAdvisoryDeterminism guards the response against map-iteration order
// leaking into the output.
func TestSearchAdvisoryDeterminism(t *testing.T) {
	respond := func(q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
		if q.Vendor == "Anthropic" {
			return advisoryResult(25, advisoryRef("CVE-B", "Beta", "Gamma")), nil
		}
		return advisoryResult(25, advisoryRef("CVE-A", "Alpha")), nil
	}

	first, _, err := runAdvisoryHandler(t, searchAdvisoryArgs{Vendor: "anthropic", Product: "nope"}, respond)
	require.NoError(t, err)
	second, _, err := runAdvisoryHandler(t, searchAdvisoryArgs{Vendor: "anthropic", Product: "nope"}, respond)
	require.NoError(t, err)

	a, err := json.Marshal(first)
	require.NoError(t, err)
	b, err := json.Marshal(second)
	require.NoError(t, err)
	assert.JSONEq(t, string(a), string(b))
}
