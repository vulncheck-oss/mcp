package client

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchPURLs(t *testing.T) {
	t.Run("sends PURLs in body and returns data", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/purls")
			var body []string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, []string{"pkg:golang/github.com/foo/bar@v1.0.0"}, body)
			return jsonResp(200, map[string]any{
				"data":  []map[string]any{{"purl": "pkg:golang/github.com/foo/bar@v1.0.0", "cves": []string{"CVE-2021-44228"}}},
				"_meta": map[string]any{"total_documents": 1},
			}), nil
		})
		result, err := vc.SearchPURLs(t.Context(), []string{"pkg:golang/github.com/foo/bar@v1.0.0"})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "pkg:golang/github.com/foo/bar@v1.0.0", *result.Data[0].Purl)
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		result, err := vc.SearchPURLs(t.Context(), []string{"pkg:golang/x@v1"})
		require.NoError(t, err)
		assert.Empty(t, result.Data)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.SearchPURLs(t.Context(), []string{"pkg:golang/x@v1"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "searching PURLs")
	})
}
