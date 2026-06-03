package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAdvisoryBackups(t *testing.T) {
	t.Run("returns backup feed items", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{
				"data": []map[string]any{
					{"name": "github-advisory", "available": true},
				},
			}), nil
		})
		items, err := vc.ListAdvisoryBackups(t.Context())
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Equal(t, "github-advisory", *items[0].Name)
		assert.True(t, *items[0].Available)
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		items, err := vc.ListAdvisoryBackups(t.Context())
		require.NoError(t, err)
		assert.Empty(t, items)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.ListAdvisoryBackups(t.Context())
		require.Error(t, err)
		assert.ErrorContains(t, err, "listing advisory backups")
	})
}
