package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchCPE(t *testing.T) {
	t.Run("maps all query fields and returns data", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/search/cpe")
			q := r.URL.Query()
			assert.Equal(t, "a", q.Get("part"))
			assert.Equal(t, "microsoft", q.Get("vendor"))
			assert.Equal(t, "office", q.Get("product"))
			assert.Equal(t, "2016", q.Get("version"))
			assert.Equal(t, "true", q.Get("isVulnerable"))
			return jsonResp(200, map[string]any{
				"data":  []map[string]any{{"cpe": "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*"}},
				"_meta": map[string]any{"total_documents": 1},
			}), nil
		})
		result, err := vc.SearchCPE(t.Context(), SearchCPEQuery{
			Part: "a", Vendor: "microsoft", Product: "office",
			Version: "2016", VulnerableOnly: true,
		})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*", *result.Data[0].Cpe)
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		result, err := vc.SearchCPE(t.Context(), SearchCPEQuery{Vendor: "x"})
		require.NoError(t, err)
		assert.Empty(t, result.Data)
		assert.Equal(t, 0, result.Total)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.SearchCPE(t.Context(), SearchCPEQuery{Vendor: "x"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "searching CPE")
	})
}
