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
					map[string]any{"name": "vendor"},
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
	assert.Equal(t, []IndexFilter{
		{Name: "date", Accepts: "YYYY-MM-DD"},
		{Name: "cve", Accepts: "CVE-YYYY-N{4-7}"},
		{Name: "vendor"},
	}, desc.Filters,
		"duplicates collapse and blank names are dropped, preserving order, and the "+
			"published values come through where the index gives one")
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

// A repeated parameter can carry the format on either entry, so the published value
// must survive whichever one appears first.
func TestDescribeIndex_KeepsAPublishedFormatFromEitherDuplicate(t *testing.T) {
	c := newAPITestClient(func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusOK, map[string]any{
			"_meta": map[string]any{
				"parameters": []any{
					map[string]any{"name": "validation_level"},
					map[string]any{"name": "validation_level", "format": "a|b|c"},
				},
			},
			"data": []any{},
		}), nil
	})

	desc, err := c.DescribeIndex(context.Background(), "exploits")
	require.NoError(t, err)
	require.Len(t, desc.Filters, 1)
	assert.Equal(t, "a|b|c", desc.Filters[0].Accepts,
		"the format is kept even when the first occurrence omits it")
}
