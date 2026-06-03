package client

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRules(t *testing.T) {
	t.Run("returns raw rule string", func(t *testing.T) {
		const ruleBody = "sigma: some detection rule"
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/rules/initial-access/sigma")
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(ruleBody)),
			}, nil
		})
		result, err := vc.GetRules(t.Context(), "sigma")
		require.NoError(t, err)
		assert.Equal(t, ruleBody, result)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.GetRules(t.Context(), "sigma")
		require.Error(t, err)
		require.ErrorContains(t, err, "getting")
		require.ErrorContains(t, err, "rules")
	})
}
