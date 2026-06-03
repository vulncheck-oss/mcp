package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchCVE(t *testing.T) {
	t.Run("maps query fields and returns data", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/search/cve")
			q := r.URL.Query()
			assert.Equal(t, "CVE-2021-44228", q.Get("cve"))
			assert.Equal(t, "10", q.Get("limit"))
			return jsonResp(200, map[string]any{
				"data": []map[string]any{
					{"id": "doc1", "index": "vulncheck-nvd2", "score": 1.5},
				},
				"_meta": map[string]any{"total_count": 1, "next_cursor": "tok123"},
			}), nil
		})
		result, err := vc.SearchCVE(t.Context(), SearchCVEQuery{CVE: "CVE-2021-44228", Limit: 10})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Equal(t, int32(1), result.Total)
		assert.Equal(t, "tok123", result.NextCursor)
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		result, err := vc.SearchCVE(t.Context(), SearchCVEQuery{CVE: "CVE-2021-44228"})
		require.NoError(t, err)
		assert.Empty(t, result.Data)
		assert.Equal(t, int32(0), result.Total)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.SearchCVE(t.Context(), SearchCVEQuery{CVE: "CVE-2021-44228"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "searching CVE")
	})
}
