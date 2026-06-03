package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchAdvisory(t *testing.T) {
	t.Run("returns data with meta", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v4")
			return jsonResp(200, map[string]any{
				"data":  []map[string]any{{"cve_id": "CVE-2021-44228"}},
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
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		result, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{})
		require.NoError(t, err)
		assert.Empty(t, result.Data)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.SearchAdvisory(t.Context(), SearchAdvisoryQuery{})
		require.Error(t, err)
		assert.ErrorContains(t, err, "searching advisories")
	})
}
