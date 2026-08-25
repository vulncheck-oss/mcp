package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

// TestResponseSizeContract is the enforcement mechanism for the contract itself.
//
// Every tool that returns API records is fed an oversized response and must answer the
// same way: within budget, with a report saying what was done to it. This is what stops
// the twelve of them growing separate answers to "the response is too big" again, which is
// the state this contract replaced — three mechanisms at two budgets covering five tools.
func TestResponseSizeContract(t *testing.T) {
	// bulkyRows builds rows whose weight is in a long array, so the array ladder has
	// something to work on.
	bulkyRows := func(n, refs int) []json.RawMessage {
		rows := make([]json.RawMessage, n)
		for i := range rows {
			rows[i] = json.RawMessage(mustMarshal(t, bulkyRecord(fmt.Sprintf("CVE-2024-%04d", i), refs)))
		}
		return rows
	}

	indexResult := func() *client.IndexQueryResult {
		return &client.IndexQueryResult{Data: bulkyRows(40, 400), Total: 5_000}
	}

	tools := []struct {
		name string
		run  func(t *testing.T) *mcp.CallToolResult
	}{
		{
			name: "search_index",
			run: func(t *testing.T) *mcp.CallToolResult {
				return runTool(t, &mockClient{
					searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
						return indexResult(), nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchIndexHandler(vc), searchIndexArgs{Index: "vulncheck-nvd2"})
				})
			},
		},
		{
			name: "search_cve",
			run: func(t *testing.T) *mcp.CallToolResult {
				hits := make([]vulncheck.IndexCveSearchHit, 40)
				for i := range hits {
					idx, id := "vulncheck-nvd2", fmt.Sprintf("CVE-2024-%04d", i)
					src := map[string]any{}
					require.NoError(t, json.Unmarshal(mustMarshal(t, bulkyRecord(id, 400)), &src))
					hits[i] = vulncheck.IndexCveSearchHit{Id: &id, Index: &idx, Source: src}
				}
				return runTool(t, &mockClient{
					searchCVEFn: func(context.Context, client.SearchCVEQuery) (*client.SearchCVEResult, error) {
						return &client.SearchCVEResult{Data: hits, Total: 40}, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchCVEHandler(vc), searchCVEArgs{CVE: "CVE-2021-44228"})
				})
			},
		},
		{
			name: "search_advisory",
			run: func(t *testing.T) *mcp.CallToolResult {
				return runTool(t, &mockClient{
					searchAdvisoryFn: func(context.Context, client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
						return &client.SearchAdvisoryResult{Data: bulkyRows(40, 400), Total: 40}, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchAdvisoryHandler(vc), searchAdvisoryArgs{Name: "ghsa"})
				})
			},
		},
		{
			name: "search_target_intel",
			run: func(t *testing.T) *mcp.CallToolResult {
				return runTool(t, &mockClient{
					searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
						return indexResult(), nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchTargetIntelHandler(vc), searchTargetIntelArgs{CVE: "CVE-2021-44228"})
				})
			},
		},
		{
			name: "search_ip_intel",
			run: func(t *testing.T) *mcp.CallToolResult {
				return runTool(t, &mockClient{
					searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
						return indexResult(), nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchIPIntelHandler(vc), searchIPIntelArgs{})
				})
			},
		},
		{
			name: "search_canaries",
			run: func(t *testing.T) *mcp.CallToolResult {
				return runTool(t, &mockClient{
					searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
						return indexResult(), nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchCanariesHandler(vc), searchCanariesArgs{})
				})
			},
		},
		{
			name: "search_curated_exploits",
			run: func(t *testing.T) *mcp.CallToolResult {
				return runTool(t, &mockClient{
					searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
						return indexResult(), nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchCuratedExploitsHandler(vc), searchCuratedExploitsArgs{})
				})
			},
		},
		{
			name: "search_cpe",
			run: func(t *testing.T) *mcp.CallToolResult {
				rows := make([]vulncheck.SearchResponseDataOut, 400)
				for i := range rows {
					cpe := fmt.Sprintf("cpe:2.3:a:vendor:product%d:*:*:*:*:*:*:*:*", i)
					cves := make([]string, 100)
					for j := range cves {
						cves[j] = fmt.Sprintf("CVE-2024-%04d", j)
					}
					rows[i] = vulncheck.SearchResponseDataOut{Cpe: &cpe, Cves: cves}
				}
				return runTool(t, &mockClient{
					searchCPEFn: func(context.Context, client.SearchCPEQuery) (*client.SearchCPEResult, error) {
						return &client.SearchCPEResult{Data: rows, Total: len(rows)}, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchCPEHandler(vc), searchCPEArgs{Vendor: "apache"})
				})
			},
		},
		{
			name: "search_purls",
			run: func(t *testing.T) *mcp.CallToolResult {
				rows := make([]vulncheck.PurlBatchVulnFinding, 3_000)
				for i := range rows {
					purl := fmt.Sprintf("pkg:npm/package%d@1.0.0", i)
					rows[i] = vulncheck.PurlBatchVulnFinding{Purl: &purl}
				}
				return runTool(t, &mockClient{
					searchPURLsFn: func(context.Context, []string) (*client.SearchPURLsResult, error) {
						return &client.SearchPURLsResult{Data: rows, Total: len(rows)}, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeSearchPURLsHandler(vc), searchPURLsArgs{PURLs: []string{"pkg:npm/x@1"}})
				})
			},
		},
		{
			name: "get_cpe_cves",
			run: func(t *testing.T) *mcp.CallToolResult {
				cves := make([]string, 40_000)
				for i := range cves {
					cves[i] = fmt.Sprintf("CVE-2024-%05d", i)
				}
				return runTool(t, &mockClient{
					getCPECVEsFn: func(context.Context, string, bool) (*client.CPECVEsResult, error) {
						return &client.CPECVEsResult{CVEs: cves, Total: len(cves)}, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeGetCPECVEsHandler(vc), getCPECVEsArgs{CPE: "cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"})
				})
			},
		},
		{
			name: "identify_component",
			run: func(t *testing.T) *mcp.CallToolResult {
				rows := make([]client.IdentifyResult, 800)
				for i := range rows {
					rows[i].Identity.Product = fmt.Sprintf("product-%d-%s", i, strings.Repeat("p", 100))
				}
				return runTool(t, &mockClient{
					identifyComponentFn: func(context.Context, string, string, string) ([]client.IdentifyResult, error) {
						return rows, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeIdentifyComponentHandler(vc), identifyComponentArgs{Vendor: "a", Product: "b"})
				})
			},
		},
		{
			name: "list_recent_advisories",
			run: func(t *testing.T) *mcp.CallToolResult {
				rows := make([]json.RawMessage, 900)
				for i := range rows {
					rows[i] = json.RawMessage(mustMarshal(t, map[string]any{
						"cveMetadata": map[string]any{
							"cveId":         fmt.Sprintf("CVE-2024-%04d", i),
							"datePublished": "2026-08-01T00:00:00Z",
						},
						"containers": map[string]any{"cna": map[string]any{
							"title": strings.Repeat("t", 200),
						}},
					}))
				}
				return runTool(t, &mockClient{
					searchAdvisoryFn: func(context.Context, client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
						return &client.SearchAdvisoryResult{Data: rows, Total: 900}, nil
					},
				}, func(vc client.Client) toolCall {
					return call(MakeListRecentAdvisoriesHandler(vc), listRecentAdvisoriesArgs{Limit: 900})
				})
			},
		},
	}

	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.run(t)

			payload := payloadText(t, result)
			assert.LessOrEqual(t, len(payload), defaultResponseBudget,
				"no tool may emit more than the budget")
			assert.True(t, json.Valid([]byte(payload)),
				"a shortened response is still valid JSON, not a truncated string")

			report := sizeReport(t, result)
			require.NotNil(t, report, "a shortened response must say what was done to it")
			assert.Equal(t, len(payload), report.Bytes)
			assert.Greater(t, report.OriginalBytes, report.Bytes)
			assert.NotEmpty(t, report.Note, "the report must say what the caller can do next")

			// Either arrays were shortened, rows were removed, or the floor was reached.
			// Silence on all three would mean a response was altered without saying so.
			assert.True(t,
				len(report.Capped) > 0 || report.Outline != nil,
				"every alteration is declared")
		})
	}
}

// TestResponseSizeContract_SmallResponsesAreUntouched pins the other half: a tool that did
// not need to shorten anything attaches no report and returns exactly what it marshalled.
func TestResponseSizeContract_SmallResponsesAreUntouched(t *testing.T) {
	result := runTool(t, &mockClient{
		searchIndexFn: func(context.Context, client.SearchIndexQuery) (*client.IndexQueryResult, error) {
			return &client.IndexQueryResult{
				Data:  []json.RawMessage{json.RawMessage(`{"cve":"CVE-2024-1"}`)},
				Total: 1,
			}, nil
		},
	}, func(vc client.Client) toolCall {
		return call(MakeSearchIndexHandler(vc), searchIndexArgs{Index: "vulncheck-nvd2"})
	})

	assert.Len(t, result.Content, 1, "nothing was done, so nothing is reported")
	assert.JSONEq(t, `{"data":[{"cve":"CVE-2024-1"}],"total":1}`, payloadText(t, result))
}

type toolCall func() (*mcp.CallToolResult, any, error)

func call[A any](h mcp.ToolHandlerFor[A, any], args A) toolCall {
	return func() (*mcp.CallToolResult, any, error) {
		return h(context.Background(), nil, args)
	}
}

func runTool(t *testing.T, mock *mockClient, build func(client.Client) toolCall) *mcp.CallToolResult {
	t.Helper()
	result, _, err := build(mock)()
	require.NoError(t, err)
	require.NotNil(t, result)
	return result
}
