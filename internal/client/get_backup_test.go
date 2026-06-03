package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBackup(t *testing.T) {
	t.Run("empty index returns ErrNoIndexArg", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("transport should not be called")
			return nil, nil
		})
		_, err := vc.GetBackup(t.Context(), "")
		require.ErrorIs(t, err, ErrNoIndexArg)
	})

	t.Run("returns backup result", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/backup/vulncheck-kev")
			return jsonResp(200, map[string]any{
				"data": []map[string]any{
					{"url": "https://example.com/backup.zip"},
				},
			}), nil
		})
		result, err := vc.GetBackup(t.Context(), "vulncheck-kev")
		require.NoError(t, err)
		assert.Equal(t, "vulncheck-kev", result.Index)
		require.Len(t, result.Data, 1)
		assert.Equal(t, "https://example.com/backup.zip", *result.Data[0].Url)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.GetBackup(t.Context(), "vulncheck-kev")
		require.Error(t, err)
		assert.ErrorContains(t, err, "getting backup")
	})
}
