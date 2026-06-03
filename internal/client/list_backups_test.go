package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListBackups(t *testing.T) {
	t.Run("returns entries", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/backup")
			return jsonResp(200, map[string]any{
				"data": []map[string]any{
					{"name": "initial-access", "description": "Initial Access"},
				},
			}), nil
		})
		entries, err := vc.ListBackups(t.Context())
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "initial-access", entries[0].Name)
		assert.Equal(t, "Initial Access", entries[0].Description)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.ListBackups(t.Context())
		require.Error(t, err)
		assert.ErrorContains(t, err, "listing backups")
	})
}
