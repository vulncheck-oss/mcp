package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAdvisories(t *testing.T) {
	t.Run("returns entries", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v4")
			return jsonResp(200, map[string]any{
				"data": []map[string]any{
					{"name": "github-advisory", "description": "GitHub Security Advisories"},
				},
			}), nil
		})
		entries, err := vc.ListAdvisories(t.Context())
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "github-advisory", entries[0].Name)
		assert.Equal(t, "GitHub Security Advisories", entries[0].Description)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.ListAdvisories(t.Context())
		require.Error(t, err)
		assert.ErrorContains(t, err, "listing advisories")
	})
}
