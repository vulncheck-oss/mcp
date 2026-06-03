package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type SearchCVEQuery struct {
	CVE         string
	Limit       int32
	Cursor      string
	StartCursor bool
}

type SearchCVEResult struct {
	Data       []vulncheck.IndexCveSearchHit `json:"data"`
	Total      int32                         `json:"total"`
	NextCursor string                        `json:"next_cursor,omitempty"`
}

func (c *VulncheckClient) SearchCVE(ctx context.Context, q SearchCVEQuery) (*SearchCVEResult, error) {
	req := c.sdk.EndpointsAPI.SearchCveGet(c.authContext(ctx)).Cve(q.CVE)
	if q.Limit > 0 {
		req = req.Limit(q.Limit)
	}
	if q.StartCursor {
		req = req.StartCursor("true")
	}
	if q.Cursor != "" {
		req = req.Cursor(q.Cursor)
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("searching CVE: %w", err)
	}

	data := resp.Data
	if data == nil {
		data = []vulncheck.IndexCveSearchHit{}
	}

	var total int32
	var nextCursor string
	if resp.Meta != nil {
		total = resp.Meta.GetTotalCount()
		nextCursor = resp.Meta.GetNextCursor()
	}

	return &SearchCVEResult{Data: data, Total: total, NextCursor: nextCursor}, nil
}
