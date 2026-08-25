//go:build live

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// TestLiveResponseSizeContract exercises the contract against the real API.
//
// Run with: go test -tags live ./internal/server/ -run TestLive -v
//
// It is behind a build tag because it needs a token and makes real requests. Everything
// the unit tests assert is asserted here too, against records whose shape and size are
// whatever the API actually returns today rather than whatever a fixture assumed.
func TestLiveResponseSizeContract(t *testing.T) {
	token := os.Getenv("VULNCHECK_API_TOKEN")
	if token == "" {
		t.Skip("VULNCHECK_API_TOKEN not set")
	}
	vc := client.New(token, "live-test")

	cases := []struct {
		name string
		call func() (*mcp.CallToolResult, any, error)
	}{
		{
			// The case in #3109: one enriched document per CVE, no row count that can
			// bound it.
			name: "search_index/nvd2/log4shell",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeSearchIndexHandler(vc)(context.Background(), nil,
					searchIndexArgs{Index: "vulncheck-nvd2", CVE: "CVE-2021-44228"})
			},
		},
		{
			name: "search_cve/log4shell",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeSearchCVEHandler(vc)(context.Background(), nil,
					searchCVEArgs{CVE: "CVE-2021-44228", Limit: 10})
			},
		},
		{
			name: "search_index/kev/log4shell",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeSearchIndexHandler(vc)(context.Background(), nil,
					searchIndexArgs{Index: "vulncheck-kev", CVE: "CVE-2021-44228"})
			},
		},
		{
			name: "search_advisory/ghsa",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeSearchAdvisoryHandler(vc)(context.Background(), nil,
					searchAdvisoryArgs{Name: "ghsa", Limit: 100})
			},
		},
		{
			name: "search_target_intel/log4shell",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeSearchTargetIntelHandler(vc)(context.Background(), nil,
					searchTargetIntelArgs{CVE: "CVE-2021-44228", Limit: 200})
			},
		},
		{
			// No limit and no cursor upstream: the query is the only lever, so this is
			// the tool most dependent on the byte budget.
			name: "get_cpe_cves/wildcard",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeGetCPECVEsHandler(vc)(context.Background(), nil,
					getCPECVEsArgs{CPE: "cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"})
			},
		},
		{
			name: "list_recent_advisories",
			call: func() (*mcp.CallToolResult, any, error) {
				return MakeListRecentAdvisoriesHandler(vc)(context.Background(), nil,
					listRecentAdvisoriesArgs{Limit: 100})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, _, err := tc.call()
			require.NoError(t, err)
			require.NotNil(t, result)

			payload := payloadText(t, result)
			report := sizeReport(t, result)

			assert.LessOrEqual(t, len(payload), defaultResponseBudget,
				"no tool may emit more than the budget")
			assert.True(t, json.Valid([]byte(payload)),
				"a shortened response is still valid JSON")

			if report == nil {
				t.Logf("within budget, untouched: %d bytes", len(payload))
				return
			}

			assert.Greater(t, report.OriginalBytes, len(payload))
			assert.NotEmpty(t, report.Note)
			assert.True(t, len(report.Capped) > 0 || report.Outline != nil,
				"every alteration is declared")

			pretty, err := json.MarshalIndent(report, "", "  ")
			require.NoError(t, err)
			t.Logf("%d -> %d bytes\n%s", report.OriginalBytes, len(payload), pretty)
		})
	}
}

// TestLiveLog4ShellIsUsable is the specific claim #3109 turns on: the record that could not
// be returned at all now comes back, capped, with its real array lengths declared.
func TestLiveLog4ShellIsUsable(t *testing.T) {
	token := os.Getenv("VULNCHECK_API_TOKEN")
	if token == "" {
		t.Skip("VULNCHECK_API_TOKEN not set")
	}

	result, _, err := MakeSearchIndexHandler(client.New(token, "live-test"))(
		context.Background(), nil,
		searchIndexArgs{Index: "vulncheck-nvd2", CVE: "CVE-2021-44228"})
	require.NoError(t, err)

	payload := payloadText(t, result)
	report := sizeReport(t, result)
	require.NotNil(t, report, "the Log4Shell record is far over budget")

	var got struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload), &got))

	require.Len(t, got.Data, 1, "the record is returned, not dropped for an empty answer")
	assert.NotEmpty(t, got.Data[0], "and it is a record, not a placeholder")

	for path, trueLen := range report.Capped {
		t.Logf("capped %s: %d items -> %d", path, trueLen, report.ArrayLimit)
		assert.Greater(t, trueLen, report.ArrayLimit,
			"only arrays that were actually shortened are reported")
	}
	fmt.Fprintf(os.Stderr, "note: %s\n", report.Note)
}
