package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// IndexQueryResult holds the parsed response from a /v3/index/{name} query.
type IndexQueryResult struct {
	Data       []json.RawMessage `json:"data"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Total      int               `json:"total"`
}

type SearchIndexQuery struct {
	Index              string
	CVE                string
	Cursor             string
	Limit              int
	StartCursor        bool
	LastModStartDate   string
	LastModEndDate     string
	PubStartDate       string
	PubEndDate         string
	UpdatedAtStartDate string
	UpdatedAtEndDate   string
	Date               string
	Alias              string
	IAVA               string
	Sort               string
	Order              string
}

type indexResponseMeta struct {
	TotalDocuments int    `json:"total_documents"`
	NextCursor     string `json:"next_cursor,omitempty"`
}

type indexResponse struct {
	Meta indexResponseMeta `json:"_meta"`
	Data json.RawMessage   `json:"data"`
}

func (c *VulncheckClient) SearchIndex(ctx context.Context, q SearchIndexQuery) (*IndexQueryResult, error) {
	if q.Index == "" {
		return nil, ErrNoIndexArg
	}

	u, err := url.Parse(c.baseURL + "/v3/index/" + url.PathEscape(q.Index))
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}

	p := u.Query()
	if q.CVE != "" {
		p.Set("cve", q.CVE)
	}
	if q.Cursor != "" {
		p.Set("cursor", q.Cursor)
	} else if q.StartCursor {
		p.Set("start_cursor", "true")
	}
	if q.Limit > 0 {
		p.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.LastModStartDate != "" {
		p.Set("lastModStartDate", q.LastModStartDate)
	}
	if q.LastModEndDate != "" {
		p.Set("lastModEndDate", q.LastModEndDate)
	}
	if q.PubStartDate != "" {
		p.Set("pubStartDate", q.PubStartDate)
	}
	if q.PubEndDate != "" {
		p.Set("pubEndDate", q.PubEndDate)
	}
	if q.UpdatedAtStartDate != "" {
		p.Set("updatedAtStartDate", q.UpdatedAtStartDate)
	}
	if q.UpdatedAtEndDate != "" {
		p.Set("updatedAtEndDate", q.UpdatedAtEndDate)
	}
	if q.Date != "" {
		p.Set("date", q.Date)
	}
	if q.Alias != "" {
		p.Set("alias", q.Alias)
	}
	if q.IAVA != "" {
		p.Set("iava", q.IAVA)
	}
	if q.Sort != "" {
		p.Set("sort", q.Sort)
	}
	if q.Order != "" {
		p.Set("order", q.Order)
	}
	u.RawQuery = p.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req) //nolint:gosec // G704: baseURL is trusted config; index name is path-escaped
	if err != nil {
		return nil, fmt.Errorf("querying index %q: %w", q.Index, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("index %q: HTTP %d: %s", q.Index, resp.StatusCode, body)
	}

	var envelope indexResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	var items []json.RawMessage
	if envelope.Data != nil {
		if err := json.Unmarshal(envelope.Data, &items); err != nil {
			return nil, fmt.Errorf("decoding data array: %w", err)
		}
	}
	if items == nil {
		items = []json.RawMessage{}
	}

	return &IndexQueryResult{
		Data:       items,
		NextCursor: envelope.Meta.NextCursor,
		Total:      envelope.Meta.TotalDocuments,
	}, nil
}
