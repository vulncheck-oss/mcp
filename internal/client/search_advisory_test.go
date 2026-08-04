package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchAdvisory(t *testing.T) {
	t.Run("returns data with meta", func(t *testing.T) {
		vc := newAPITestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "/v4/advisory", r.URL.Path)
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			assert.Equal(t, "vulncheck-mcp/test", r.Header.Get("User-Agent"))
			assert.Equal(t, "CVE-2021-44228", r.URL.Query().Get("cve_id"))
			assert.Equal(t, "10", r.URL.Query().Get("limit"))
			return jsonResp(200, map[string]any{
				"data":  []map[string]any{{"cveMetadata": map[string]any{"cveId": "CVE-2021-44228"}}},
				"_meta": map[string]any{"total": 1, "next_cursor": "cursor-abc"},
			}), nil
		})
		result, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{
			CveID: "CVE-2021-44228", Limit: 10,
		})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Equal(t, int32(1), result.Total)
		assert.Equal(t, "cursor-abc", result.NextCursor)
		assert.JSONEq(t, `{"cveMetadata":{"cveId":"CVE-2021-44228"}}`, string(result.Data[0]))
	})

	// The reason records are carried as json.RawMessage: the API serves
	// containers.cna.source and containers.adp[].metrics[].other.content as JSON
	// strings wrapping JSON objects, which the generated SDK types reject outright.
	t.Run("decodes a record the generated SDK types reject", func(t *testing.T) {
		vc := newAPITestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{
				"data": []map[string]any{{
					"cveMetadata": map[string]any{"cveId": "CVE-2025-59532"},
					"containers": map[string]any{
						"cna": map[string]any{
							// double-encoded; the SDK declares this []int32
							"source": `{"advisory":"GHSA-w5fx-fh39-j5rw","discovery":"UNKNOWN"}`,
						},
						"adp": []map[string]any{{
							"metrics": []map[string]any{{
								// double-encoded; the SDK declares this map[string]any
								"other": map[string]any{"type": "ssvc", "content": `{"id":"CVE-2025-59532"}`},
							}},
						}},
					},
				}},
				"_meta": map[string]any{"total": 1},
			}), nil
		})
		result, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{CveID: "CVE-2025-59532"})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Contains(t, string(result.Data[0]), "GHSA-w5fx-fh39-j5rw",
			"the record reaches the caller verbatim")
	})

	t.Run("sends every filter as a query parameter", func(t *testing.T) {
		vc := newAPITestClient(func(r *http.Request) (*http.Response, error) {
			q := r.URL.Query()
			assert.Equal(t, "ghsa", q.Get("name"))
			assert.Equal(t, "Anthropic", q.Get("vendor"), "vendor case must survive verbatim")
			assert.Equal(t, "Claude Desktop - Windows", q.Get("product"))
			assert.Equal(t, "@anthropic-ai/claude-code", q.Get("package_name"))
			assert.Equal(t, "now-30d", q.Get("updatedAfter"))
			return jsonResp(200, map[string]any{"data": []any{}}), nil
		})
		_, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{
			Name:         "ghsa",
			Vendor:       "Anthropic",
			Product:      "Claude Desktop - Windows",
			PackageName:  "@anthropic-ai/claude-code",
			UpdatedAfter: "now-30d",
		})
		require.NoError(t, err)
	})

	t.Run("start_cursor is dropped once a cursor is supplied", func(t *testing.T) {
		vc := newAPITestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "page2", r.URL.Query().Get("cursor"))
			assert.Empty(t, r.URL.Query().Get("start_cursor"))
			return jsonResp(200, map[string]any{"data": []any{}}), nil
		})
		_, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{
			Cursor: "page2", StartCursor: true,
		})
		require.NoError(t, err)
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newAPITestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		result, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{})
		require.NoError(t, err)
		assert.Empty(t, result.Data)
		assert.NotNil(t, result.Data, "an empty list must not marshal as null")
	})

	t.Run("HTTP error wraps with context", func(t *testing.T) {
		vc := newAPITestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{})
		require.Error(t, err)
		require.ErrorContains(t, err, "searching advisories")
		require.ErrorContains(t, err, "500")
	})

	t.Run("malformed body reports a decode failure", func(t *testing.T) {
		vc := newAPITestClient(func(_ *http.Request) (*http.Response, error) {
			resp := jsonResp(200, map[string]any{})
			resp.Body = http.NoBody
			return resp, nil
		})
		_, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{})
		require.Error(t, err)
		assert.ErrorContains(t, err, "decoding response")
	})
}
