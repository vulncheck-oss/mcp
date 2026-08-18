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

func advisoryRaw(cve, title, provider, published, updated, desc, ref string) json.RawMessage {
	rec := map[string]any{
		"cveMetadata": map[string]any{"cveId": cve, "datePublished": published},
		"containers": map[string]any{"cna": map[string]any{
			"title":            title,
			"providerMetadata": map[string]any{"shortName": provider, "dateUpdated": updated},
			"descriptions":     []any{map[string]any{"value": desc}},
			"references":       []any{map[string]any{"url": ref}},
		}},
	}
	b, _ := json.Marshal(rec)
	return b
}

func captureAdvisory(got *client.SearchAdvisoryQuery, resp *client.SearchAdvisoryResult) *mockClient {
	return &mockClient{
		searchAdvisoryFn: func(_ context.Context, q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
			*got = q
			if resp != nil {
				return resp, nil
			}
			return &client.SearchAdvisoryResult{Data: []json.RawMessage{}}, nil
		},
	}
}

func TestListRecentAdvisories_DefaultsToTheLastDay(t *testing.T) {
	var got client.SearchAdvisoryQuery
	_, _, err := MakeListRecentAdvisoriesHandler(captureAdvisory(&got, nil))(
		context.Background(), nil, listRecentAdvisoriesArgs{})
	require.NoError(t, err)

	assert.Equal(t, defaultRecentWindow, got.UpdatedAfter,
		"the common question is what changed since yesterday, so it needs no arguments")
	assert.Equal(t, int32(defaultRecentLimit), got.Limit)
}

func TestListRecentAdvisories_PassesFiltersThrough(t *testing.T) {
	var got client.SearchAdvisoryQuery
	_, _, err := MakeListRecentAdvisoriesHandler(captureAdvisory(&got, nil))(
		context.Background(), nil, listRecentAdvisoriesArgs{
			Since: "now-7d", Until: "now-1d", Name: "ghsa",
			Vendor: "Acme", Product: "Widget", Limit: 40, Cursor: "abc",
		})
	require.NoError(t, err)

	assert.Equal(t, "now-7d", got.UpdatedAfter)
	assert.Equal(t, "now-1d", got.UpdatedBefore)
	assert.Equal(t, "ghsa", got.Name)
	assert.Equal(t, "Acme", got.Vendor)
	assert.Equal(t, "Widget", got.Product)
	assert.Equal(t, int32(40), got.Limit)
	assert.Equal(t, "abc", got.Cursor)
}

func TestListRecentAdvisories_ClampsLimit(t *testing.T) {
	var got client.SearchAdvisoryQuery
	_, _, err := MakeListRecentAdvisoriesHandler(captureAdvisory(&got, nil))(
		context.Background(), nil, listRecentAdvisoriesArgs{Limit: 5000})
	require.NoError(t, err)
	assert.Equal(t, int32(maxRecentLimit), got.Limit)
}

// The projection is the point of this tool: a caller should be able to decide whether
// a record is worth fetching in full without receiving the record.
func TestProjectAdvisory_KeepsIdentityProvenanceAndTiming(t *testing.T) {
	row := projectAdvisory(advisoryRaw(
		"CVE-2026-0001", "Widget RCE", "acme", "2026-08-01T00:00:00Z", "2026-08-17T00:00:00Z",
		"A long description", "https://example.com/advisory"))

	assert.Equal(t, "CVE-2026-0001", row.CVE)
	assert.Equal(t, "Widget RCE", row.Title)
	assert.Equal(t, "acme", row.Provider)
	assert.Equal(t, "2026-08-01T00:00:00Z", row.Published)
	assert.Equal(t, "2026-08-17T00:00:00Z", row.Updated)
	assert.Equal(t, "https://example.com/advisory", row.Reference)
}

// Some feeds carry no title at all, so the description's first sentence stands in.
func TestProjectAdvisory_FallsBackToDescriptionWhenTitleIsAbsent(t *testing.T) {
	row := projectAdvisory(advisoryRaw(
		"CVE-2026-0002", "", "acme", "", "",
		"Improper input validation in Widget. Further detail follows.", ""))

	assert.Equal(t, "Improper input validation in Widget", row.Title,
		"the first sentence stands in for a missing title")
}

func TestProjectAdvisory_TruncatesAnOverlongFallback(t *testing.T) {
	row := projectAdvisory(advisoryRaw("CVE-2026-0003", "", "acme", "", "",
		strings.Repeat("x", 400), ""))

	assert.LessOrEqual(t, len([]rune(row.Title)), maxDigestTitle+1,
		"one verbose entry must not dominate the digest")
}

// A record that will not parse still yields a row. Dropping it would understate the
// page and make returned disagree with what the API sent.
func TestProjectAdvisory_UnparseableRecordStillYieldsARow(t *testing.T) {
	row := projectAdvisory(json.RawMessage(`not json`))
	assert.Empty(t, row.CVE)

	got := buildRecentAdvisories(&client.SearchAdvisoryResult{
		Data:  []json.RawMessage{json.RawMessage(`not json`)},
		Total: 1,
	}, "now-24h", "", "")
	assert.Equal(t, 1, got.Returned)
	assert.Len(t, got.Data, 1)
}

func TestBuildRecentAdvisories_SummarisesProviders(t *testing.T) {
	got := buildRecentAdvisories(&client.SearchAdvisoryResult{
		Data: []json.RawMessage{
			advisoryRaw("CVE-1", "a", "ghsa", "", "", "", ""),
			advisoryRaw("CVE-2", "b", "ghsa", "", "", "", ""),
			advisoryRaw("CVE-3", "c", "redhat", "", "", "", ""),
		},
		Total: 3,
	}, "now-24h", "", "")

	assert.Equal(t, map[string]int{"ghsa": 2, "redhat": 1}, got.Providers)
	assert.Equal(t, 3, got.Returned)
	assert.Contains(t, strings.Join(got.Notes, " "), "digest")
}

// A feed mid-bulk-update can fill the page and make it look as though little else
// changed. Saying so is the difference between a useful digest and a misleading one.
func TestBuildRecentAdvisories_FlagsSingleFeedDomination(t *testing.T) {
	rows := make([]json.RawMessage, 20)
	for i := range rows {
		rows[i] = advisoryRaw(fmt.Sprintf("CVE-%d", i), "t", "exploits-v3", "", "", "", "")
	}

	got := buildRecentAdvisories(&client.SearchAdvisoryResult{Data: rows, Total: 400000}, "now-24h", "", "")
	assert.Contains(t, strings.Join(got.Notes, " "), "mid-bulk-update")

	t.Run("not flagged when the caller already chose a feed", func(t *testing.T) {
		scoped := buildRecentAdvisories(&client.SearchAdvisoryResult{Data: rows, Total: 400000}, "now-24h", "", "exploits-v3")
		assert.NotContains(t, strings.Join(scoped.Notes, " "), "mid-bulk-update",
			"asking for one feed and getting one feed is not a surprise")
	})

	t.Run("not flagged on a mixed page", func(t *testing.T) {
		mixed := make([]json.RawMessage, 0, 20)
		for i := range 20 {
			p := "ghsa"
			if i%2 == 0 {
				p = "redhat"
			}
			mixed = append(mixed, advisoryRaw(fmt.Sprintf("CVE-%d", i), "t", p, "", "", "", ""))
		}
		got := buildRecentAdvisories(&client.SearchAdvisoryResult{Data: mixed, Total: 100}, "now-24h", "", "")
		assert.NotContains(t, strings.Join(got.Notes, " "), "mid-bulk-update")
	})
}

func TestBuildRecentAdvisories_CapsTheProviderBreakdown(t *testing.T) {
	rows := make([]json.RawMessage, 0, 40)
	for i := range 40 {
		rows = append(rows, advisoryRaw(fmt.Sprintf("CVE-%d", i), "t", fmt.Sprintf("feed-%02d", i), "", "", "", ""))
	}
	got := buildRecentAdvisories(&client.SearchAdvisoryResult{Data: rows, Total: 40}, "now-24h", "", "")
	assert.Len(t, got.Providers, maxDigestSummaryEntries,
		"a diverse page must not crowd out the rows it describes")
}

func TestBuildRecentAdvisories_ReportsTheWindow(t *testing.T) {
	open := buildRecentAdvisories(&client.SearchAdvisoryResult{}, "now-24h", "", "")
	assert.Equal(t, "updated after now-24h", open.Window)

	bounded := buildRecentAdvisories(&client.SearchAdvisoryResult{}, "now-7d", "now-1d", "")
	assert.Equal(t, "updated between now-7d and now-1d", bounded.Window)
}

func TestListRecentAdvisories_SerializesTheDigest(t *testing.T) {
	var got client.SearchAdvisoryQuery
	vc := captureAdvisory(&got, &client.SearchAdvisoryResult{
		Data:       []json.RawMessage{advisoryRaw("CVE-2026-9", "Thing", "ghsa", "p", "u", "", "https://x")},
		Total:      408894,
		NextCursor: "next",
	})

	res, _, err := MakeListRecentAdvisoriesHandler(vc)(context.Background(), nil, listRecentAdvisoriesArgs{})
	require.NoError(t, err)
	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok)

	var payload recentAdvisoriesResponse
	require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
	assert.Equal(t, int32(408894), payload.Total)
	assert.Equal(t, 1, payload.Returned)
	assert.Equal(t, "next", payload.NextCursor)
	require.Len(t, payload.Data, 1)
	assert.Equal(t, "CVE-2026-9", payload.Data[0].CVE)
	assert.Contains(t, strings.Join(payload.Notes, " "), "current page")
}

func TestListRecentAdvisories_PropagatesClientErrors(t *testing.T) {
	vc := &mockClient{
		searchAdvisoryFn: func(_ context.Context, _ client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
			return nil, errors.New("upstream exploded")
		},
	}
	_, _, err := MakeListRecentAdvisoriesHandler(vc)(context.Background(), nil, listRecentAdvisoriesArgs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recent advisories")
}
