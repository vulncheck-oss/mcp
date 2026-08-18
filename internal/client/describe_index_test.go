package client

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDescribeIndex(t *testing.T) {
	var got *url.URL
	c := newAPITestClient(func(r *http.Request) (*http.Response, error) {
		got = r.URL
		return jsonResp(http.StatusOK, map[string]any{
			"_meta": map[string]any{
				"total_documents": 384273,
				"sort":            "lastModified",
				"parameters": []any{
					// The upstream list repeats a name; the caller should see it once.
					map[string]any{"name": "date", "format": "YYYY-MM-DD"},
					map[string]any{"name": "date", "format": "YYYY-MM-DD"},
					map[string]any{"name": "cve", "format": "CVE-YYYY-N{4-7}"},
					map[string]any{"name": ""},
				},
			},
			"data": []any{},
		}), nil
	})

	desc, err := c.DescribeIndex(context.Background(), "vulncheck-nvd2")
	require.NoError(t, err)

	assert.Equal(t, "/v3/index/vulncheck-nvd2", got.Path)
	assert.Equal(t, "1", got.Query().Get("limit"),
		"one document is enough, since the metadata does not depend on the page")
	assert.Equal(t, "vulncheck-nvd2", desc.Name)
	assert.Equal(t, 384273, desc.TotalDocuments)
	assert.Equal(t, "lastModified", desc.DefaultSort)
	assert.Equal(t, []string{"date", "cve"}, desc.Filters,
		"duplicates collapse and blank names are dropped, preserving order")
}

func TestDescribeIndex_RequiresAnIndex(t *testing.T) {
	c := newAPITestClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("no request should be made without an index")
		return nil, nil
	})
	_, err := c.DescribeIndex(context.Background(), "")
	require.ErrorIs(t, err, ErrNoIndexArg)
}

func TestDescribeIndex_SurfacesHTTPErrors(t *testing.T) {
	c := newAPITestClient(func(*http.Request) (*http.Response, error) {
		return errResp(http.StatusNotFound), nil
	})
	_, err := c.DescribeIndex(context.Background(), "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}
