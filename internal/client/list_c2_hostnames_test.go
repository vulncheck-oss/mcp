package client

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListC2Hostnames(t *testing.T) {
	t.Run("returns raw string", func(t *testing.T) {
		const body = "192.168.1.1\n10.0.0.1"
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/pdns/vulncheck-c2")
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})
		result, err := vc.ListC2Hostnames(t.Context())
		require.NoError(t, err)
		assert.Equal(t, body, result)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.ListC2Hostnames(t.Context())
		require.Error(t, err)
		assert.ErrorContains(t, err, "listing C2 hostnames")
	})
}
