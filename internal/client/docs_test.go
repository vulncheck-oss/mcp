package client

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchDocs(t *testing.T) {
	t.Run("returns index content", func(t *testing.T) {
		const body = "# VulnCheck Documentation\nhttps://docs.vulncheck.com/raw/getting-started.md\n"
		vc := newDocsTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "/llms.txt", r.URL.Path)
			assert.Equal(t, "vulncheck-mcp/test", r.Header.Get("User-Agent"))
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})
		result, err := vc.SearchDocs(t.Context())
		require.NoError(t, err)
		assert.Equal(t, body, result)
	})

	t.Run("non-200 returns error", func(t *testing.T) {
		vc := newDocsTestClient(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 503,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})
		_, err := vc.SearchDocs(t.Context())
		require.Error(t, err)
		assert.ErrorContains(t, err, "searching docs")
	})

	t.Run("network error wraps with context", func(t *testing.T) {
		vc := newDocsTestClient(func(_ *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("connection refused")
		})
		_, err := vc.SearchDocs(t.Context())
		require.Error(t, err)
		assert.ErrorContains(t, err, "searching docs")
	})
}

func TestGetDoc(t *testing.T) {
	const validURL = "https://docs.vulncheck.com/raw/getting-started/api-tokens.md"
	const body = "# API Tokens\nCreate tokens at console.vulncheck.com\n"

	t.Run("returns markdown content", func(t *testing.T) {
		vc := newDocsTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, validURL, r.URL.String())
			assert.Equal(t, "vulncheck-mcp/test", r.Header.Get("User-Agent"))
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})
		result, err := vc.GetDoc(t.Context(), validURL)
		require.NoError(t, err)
		assert.Equal(t, body, result)
	})

	t.Run("invalid URL wrong host", func(t *testing.T) {
		vc := newDocsTestClient(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("should not make HTTP call for invalid URL")
			return nil, nil
		})
		_, err := vc.GetDoc(t.Context(), "https://evil.example.com/raw/foo.md")
		require.Error(t, err)
		assert.ErrorContains(t, err, "invalid doc URL")
	})

	t.Run("invalid URL missing .md suffix", func(t *testing.T) {
		vc := newDocsTestClient(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("should not make HTTP call for invalid URL")
			return nil, nil
		})
		_, err := vc.GetDoc(t.Context(), "https://docs.vulncheck.com/raw/getting-started")
		require.Error(t, err)
		assert.ErrorContains(t, err, "invalid doc URL")
	})

	t.Run("non-200 returns error", func(t *testing.T) {
		vc := newDocsTestClient(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 404,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})
		_, err := vc.GetDoc(t.Context(), validURL)
		require.Error(t, err)
		assert.ErrorContains(t, err, "fetching doc")
	})

	t.Run("network error wraps with context", func(t *testing.T) {
		vc := newDocsTestClient(func(_ *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("connection refused")
		})
		_, err := vc.GetDoc(t.Context(), validURL)
		require.Error(t, err)
		assert.ErrorContains(t, err, "fetching doc")
	})
}
