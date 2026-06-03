package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAdvisoryBackup(t *testing.T) {
	t.Run("returns backup response", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "github-advisory")
			return jsonResp(200, map[string]any{
				"feed":      "github-advisory",
				"available": true,
			}), nil
		})
		result, err := vc.GetAdvisoryBackup(t.Context(), "github-advisory")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "github-advisory", *result.Feed)
		assert.True(t, *result.Available)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.GetAdvisoryBackup(t.Context(), "github-advisory")
		require.Error(t, err)
		assert.ErrorContains(t, err, "getting advisory backup")
	})
}
