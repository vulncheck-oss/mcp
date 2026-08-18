package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// IndexDescription reports what an index holds and which filters it accepts.
type IndexDescription struct {
	Name string `json:"name"`

	// Filters are the query parameters the index reports as supported, each with the
	// accepted values or pattern where the index publishes one. This is the index's own
	// account of itself, which is more current than any documentation — and in at least
	// one case contradicts it.
	Filters []IndexFilter `json:"filters"`

	// TotalDocuments is the size of the index, useful for judging whether a query
	// against it needs narrowing before it is worth running.
	TotalDocuments int `json:"total_documents"`

	// DefaultSort is the field the index orders by when none is requested.
	DefaultSort string `json:"default_sort,omitempty"`
}

// IndexFilter is one supported query parameter.
type IndexFilter struct {
	Name string `json:"name"`

	// Accepts is the values or pattern the index publishes for this parameter, verbatim
	// — a closed vocabulary as alternatives, or a regular expression or date layout for
	// free-form parameters. Empty when the index publishes none.
	//
	// This is the authoritative vocabulary. Guessing at one, or taking it from
	// documentation, has produced filters that were silently ignored.
	Accepts string `json:"accepts,omitempty"`
}

// describeMeta is the subset of the index envelope this needs.
type describeMeta struct {
	Meta struct {
		TotalDocuments int    `json:"total_documents"`
		Sort           string `json:"sort"`
		Parameters     []struct {
			Name   string `json:"name"`
			Format string `json:"format"`
		} `json:"parameters"`
	} `json:"_meta"`
}

// DescribeIndex reports an index's supported filters by making the smallest possible
// query against it and reading the metadata the response carries.
//
// There is no dedicated endpoint for this, and asking for the filters of all indices
// at once would mean a request each, so this describes one index at a time.
func (c *VulncheckClient) DescribeIndex(ctx context.Context, index string) (*IndexDescription, error) {
	if index == "" {
		return nil, ErrNoIndexArg
	}

	u, err := url.Parse(c.baseURL + "/v3/index/" + url.PathEscape(index))
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}
	q := u.Query()
	// One document is enough: the metadata this reads does not depend on the page.
	q.Set("limit", "1")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req) //nolint:gosec // G704: baseURL is trusted config; index name is path-escaped
	if err != nil {
		return nil, fmt.Errorf("describing index %q: %w", index, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("index %q: HTTP %d: %s", index, resp.StatusCode, body)
	}

	var envelope describeMeta
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// The parameter list can repeat a name; de-duplicate so the caller sees each filter
	// once, preferring whichever entry carries a published format.
	seenAt := map[string]int{}
	filters := make([]IndexFilter, 0, len(envelope.Meta.Parameters))
	for _, p := range envelope.Meta.Parameters {
		if p.Name == "" {
			continue
		}
		if at, seen := seenAt[p.Name]; seen {
			if filters[at].Accepts == "" {
				filters[at].Accepts = p.Format
			}
			continue
		}
		seenAt[p.Name] = len(filters)
		filters = append(filters, IndexFilter{Name: p.Name, Accepts: p.Format})
	}

	return &IndexDescription{
		Name:           index,
		Filters:        filters,
		TotalDocuments: envelope.Meta.TotalDocuments,
		DefaultSort:    envelope.Meta.Sort,
	}, nil
}
