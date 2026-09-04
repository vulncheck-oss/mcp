package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

// envelopeCase is one record-returning tool, run against a mock that returns rowCount rows
// and, where the tool paginates, a cursor.
type envelopeCase struct {
	name string

	// paginates records whether next_cursor is meaningful. It is omitempty, so asserting
	// on it for a tool that never sets one would pass vacuously and prove nothing.
	paginates bool

	run func(t *testing.T, rowCount int) *mcp.CallToolResult
}

// envelopeCases covers the twelve tools that call capResult — the same set
// TestResponseSizeContract enumerates, which is what makes "record-returning tool" a
// definition in the code rather than a judgement call.
func envelopeCases() []envelopeCase {
	// rawRows builds n trivially small records, so nothing here is near the byte budget:
	// this contract is about the unshortened path.
	rawRows := func(n int) []json.RawMessage {
		rows := make([]json.RawMessage, n)
		for i := range rows {
			rows[i] = json.RawMessage(`{"cve":"CVE-2024-0001"}`)
		}
		return rows
	}
	indexResult := func(n int) *client.IndexQueryResult {
		return &client.IndexQueryResult{Data: rawRows(n), Total: 500, NextCursor: "next"}
	}
	indexMock := func(n int) *mockClient {
		return &mockClient{searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
			return indexResult(n), nil
		}}
	}

	return []envelopeCase{
		{
			name:      "search_index",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				return runTool(t, indexMock(n), func(vc client.Client) toolCall {
					return call(MakeSearchIndexHandler(vc), searchIndexArgs{Index: "vulncheck-nvd2"})
				})
			},
		},
		{
			name:      "search_target_intel",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				return runTool(t, indexMock(n), func(vc client.Client) toolCall {
					return call(MakeSearchTargetIntelHandler(vc), searchTargetIntelArgs{CVE: "CVE-2021-44228"})
				})
			},
		},
		{
			name:      "search_ip_intel",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				return runTool(t, indexMock(n), func(vc client.Client) toolCall {
					return call(MakeSearchIPIntelHandler(vc), searchIPIntelArgs{})
				})
			},
		},
		{
			name:      "search_canaries",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				return runTool(t, indexMock(n), func(vc client.Client) toolCall {
					return call(MakeSearchCanariesHandler(vc), searchCanariesArgs{})
				})
			},
		},
		{
			name:      "search_curated_exploits",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				return runTool(t, indexMock(n), func(vc client.Client) toolCall {
					return call(MakeSearchCuratedExploitsHandler(vc), searchCuratedExploitsArgs{})
				})
			},
		},
		{
			name:      "search_advisory",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				mock := &mockClient{searchAdvisoryFn: func(context.Context, client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
					return &client.SearchAdvisoryResult{Data: rawRows(n), Total: int32(n), NextCursor: "next"}, nil //nolint:gosec // G115: n is a row count set by this test, never near the int32 bound
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeSearchAdvisoryHandler(vc), searchAdvisoryArgs{Name: "ghsa"})
				})
			},
		},
		{
			name:      "list_recent_advisories",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				rows := make([]json.RawMessage, n)
				for i := range rows {
					rows[i] = json.RawMessage(`{"cveMetadata":{"cveId":"CVE-2024-0001"}}`)
				}
				mock := &mockClient{searchAdvisoryFn: func(context.Context, client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
					return &client.SearchAdvisoryResult{Data: rows, Total: int32(n), NextCursor: "next"}, nil //nolint:gosec // G115: as above
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeListRecentAdvisoriesHandler(vc), listRecentAdvisoriesArgs{})
				})
			},
		},
		{
			name:      "search_cve",
			paginates: true,
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				hits := make([]vulncheck.IndexCveSearchHit, n)
				mock := &mockClient{searchCVEFn: func(context.Context, client.SearchCVEQuery) (*client.SearchCVEResult, error) {
					return &client.SearchCVEResult{Data: hits, Total: int32(n), NextCursor: "next"}, nil //nolint:gosec // G115: as above
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeSearchCVEHandler(vc), searchCVEArgs{CVE: "CVE-2021-44228"})
				})
			},
		},
		{
			name: "search_cpe",
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				rows := make([]vulncheck.SearchResponseDataOut, n)
				mock := &mockClient{searchCPEFn: func(context.Context, client.SearchCPEQuery) (*client.SearchCPEResult, error) {
					return &client.SearchCPEResult{Data: rows, Total: n}, nil
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeSearchCPEHandler(vc), searchCPEArgs{Vendor: "apache"})
				})
			},
		},
		{
			name: "search_purls",
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				// An empty slice rather than nil, because that is what client.SearchPURLs
				// guarantees. The defect this tool had was returning the client result
				// directly, whose Data was tagged omitempty and so vanished when empty.
				rows := make([]vulncheck.PurlBatchVulnFinding, n)
				mock := &mockClient{searchPURLsFn: func(context.Context, []string) (*client.SearchPURLsResult, error) {
					return &client.SearchPURLsResult{Data: rows, Total: n}, nil
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeSearchPURLsHandler(vc), searchPURLsArgs{PURLs: []string{"pkg:npm/x@1"}})
				})
			},
		},
		{
			name: "get_cpe_cves",
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				cves := make([]string, n)
				for i := range cves {
					cves[i] = "CVE-2024-0001"
				}
				mock := &mockClient{getCPECVEsFn: func(context.Context, string, bool) (*client.CPECVEsResult, error) {
					return &client.CPECVEsResult{CVEs: cves, Total: n}, nil
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeGetCPECVEsHandler(vc), getCPECVEsArgs{CPE: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"})
				})
			},
		},
		{
			name: "identify_component",
			run: func(t *testing.T, n int) *mcp.CallToolResult {
				rows := make([]client.IdentifyResult, n)
				mock := &mockClient{identifyComponentFn: func(context.Context, string, string, string) ([]client.IdentifyResult, error) {
					return rows, nil
				}}
				return runTool(t, mock, func(vc client.Client) toolCall {
					return call(MakeIdentifyComponentHandler(vc), identifyComponentArgs{Vendor: "a", Product: "b"})
				})
			},
		},
	}
}

// decodePayload returns the response as a bare map, so a field's *presence* can be asserted
// rather than the zero value a typed decode would invent for a field that is missing.
func decodePayload(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	return decodeNumeric(t, payloadText(t, result))
}

// decodeNumeric decodes with UseNumber, so a row count arrives as json.Number rather than
// float64 and can be compared exactly. These are integer counts: comparing them as floats
// invites an epsilon, and an epsilon on "how many rows are present" is meaningless. cap.go
// decodes the same way, for the neighbouring reason that float64 loses large integers.
func decodeNumeric(t *testing.T, encoded string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(encoded))
	dec.UseNumber()
	var payload map[string]any
	require.NoError(t, dec.Decode(&payload))
	return payload
}

// TestEnvelopeContract is the enforcement mechanism for the response envelope.
//
// Every tool that returns API records reports the same core — the rows, how many are
// present, how many matched, and where the next page is — so a caller does not have to know
// which tool it called to read the answer. Twelve tools grew that reporting separately and
// six of them never got it; this is what stops that recurring.
func TestEnvelopeContract(t *testing.T) {
	for _, tc := range envelopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			payload := decodePayload(t, tc.run(t, 3))

			require.Contains(t, payload, "data", "rows live under data on every tool")
			require.Contains(t, payload, "returned", "a tool must say how many rows it returned")
			require.Contains(t, payload, "total", "a tool must say how many matched")

			assert.Equal(t, json.Number("3"), payload["returned"],
				"returned counts the rows actually present")

			if tc.paginates {
				assert.Equal(t, "next", payload["next_cursor"],
					"a paginating tool passes the cursor through")
			}
		})
	}
}

// TestEnvelopeContract_EmptyResultsAreExplicit is the half that matters most.
//
// An empty result must be visibly empty rather than absent. A missing `data` or a missing
// `returned` reads as a malfunction, and "nothing matched" and "something went wrong" must
// not look the same to a caller about to report that nothing is affected.
func TestEnvelopeContract_EmptyResultsAreExplicit(t *testing.T) {
	for _, tc := range envelopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			payload := decodePayload(t, tc.run(t, 0))

			require.Contains(t, payload, "data",
				"data is present even when empty — absence is not a way to say zero")
			require.Contains(t, payload, "returned",
				"returned is present at zero, which is the value most worth reporting")
			assert.Equal(t, json.Number("0"), payload["returned"])
			require.Contains(t, payload, "total")
		})
	}
}

// TestEnvelopeMarshalsEveryField guards the failure that has no symptom.
//
// encoding/json drops *every* conflicting field name at a given depth and returns no error.
// searchAdvisoryResponse embedded *client.SearchAdvisoryResult, which promotes `total` and
// `next_cursor` to the depth envelope also occupies, so adding the envelope without
// flattening it first would have emitted neither — err == nil, and nothing else in the
// suite watching, because TestResponseSizeContract asserts on the size report.
//
// This walks the tools' own result types rather than a hand-written copy of their shape, so
// a future struct that reintroduces the collision fails here.
func TestEnvelopeMarshalsEveryField(t *testing.T) {
	core := envelope{Returned: 1, Total: 42, NextCursor: "abc", Notes: []string{"note"}}

	results := map[string]any{
		"searchIndexResult":        searchIndexResult{Data: []json.RawMessage{json.RawMessage(`{}`)}, envelope: core},
		"searchAdvisoryResponse":   searchAdvisoryResponse{Data: []json.RawMessage{json.RawMessage(`{}`)}, envelope: core},
		"productResponse":          productResponse{Index: "i", Data: []json.RawMessage{json.RawMessage(`{}`)}, envelope: core},
		"recentAdvisoriesResponse": recentAdvisoriesResponse{Data: []advisoryDigestRow{{}}, Window: "w", envelope: core},
		"searchCVEResult":          searchCVEResult{Data: []vulncheck.IndexCveSearchHit{{}}, envelope: core},
		"searchCPEResult":          searchCPEResult{Data: []vulncheck.SearchResponseDataOut{{}}, envelope: core},
		"searchPURLsResult":        searchPURLsResult{Data: []vulncheck.PurlBatchVulnFinding{{}}, envelope: core},
		"identifyComponentResult":  identifyComponentResult{Data: []client.IdentifyResult{{}}, envelope: core},
		"getCPECVEsResult":         getCPECVEsResult{CPE: "c", Data: []string{"CVE-2024-0001"}, envelope: core},
		"searchDocsResult":         searchDocsResult{Query: "q", Data: []DocPage{{}}, envelope: core},
	}

	for name, v := range results {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(v)
			require.NoError(t, err)

			got := decodeNumeric(t, string(encoded))

			for _, field := range []string{"data", "returned", "total", "next_cursor", "notes"} {
				assert.Contains(t, got, field,
					"%s: a field colliding with an embedded struct is dropped without error", field)
			}
			assert.Equal(t, json.Number("42"), got["total"], "total must survive, not be silently dropped")
			assert.Equal(t, "abc", got["next_cursor"])
		})
	}
}
