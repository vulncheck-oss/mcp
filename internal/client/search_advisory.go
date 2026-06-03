package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type SearchAdvisoryQuery struct {
	Name          string
	CveID         string
	Vendor        string
	Product       string
	Platform      string
	Version       string
	CPE           string
	PackageName   string
	PURL          string
	UpdatedAfter  string
	UpdatedBefore string
	Limit         int32
	StartCursor   bool
	Cursor        string
}

type SearchAdvisoryResult struct {
	Data       []vulncheck.AdvisoryMitreCVEListV5Ref `json:"data"`
	Total      int32                                 `json:"total"`
	NextCursor string                                `json:"next_cursor,omitempty"`
}

func (c *VulncheckClient) SearchAdvisory(ctx context.Context, q SearchAdvisoryQuery) (*SearchAdvisoryResult, error) {
	req := c.sdk.AdvisoryAPI.V4QueryAdvisories(c.authContext(ctx))
	if q.Name != "" {
		req = req.Name(q.Name)
	}
	if q.CveID != "" {
		req = req.CveId(q.CveID)
	}
	if q.Vendor != "" {
		req = req.Vendor(q.Vendor)
	}
	if q.Product != "" {
		req = req.Product(q.Product)
	}
	if q.Platform != "" {
		req = req.Platform(q.Platform)
	}
	if q.Version != "" {
		req = req.Version(q.Version)
	}
	if q.CPE != "" {
		req = req.Cpe(q.CPE)
	}
	if q.PackageName != "" {
		req = req.PackageName(q.PackageName)
	}
	if q.PURL != "" {
		req = req.Purl(q.PURL)
	}
	if q.UpdatedAfter != "" {
		req = req.UpdatedAfter(q.UpdatedAfter)
	}
	if q.UpdatedBefore != "" {
		req = req.UpdatedBefore(q.UpdatedBefore)
	}
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
		return nil, fmt.Errorf("searching advisories: %w", err)
	}

	data := resp.Data
	if data == nil {
		data = []vulncheck.AdvisoryMitreCVEListV5Ref{}
	}

	var total int32
	var nextCursor string
	if resp.Meta != nil {
		total = resp.Meta.GetTotal()
		nextCursor = resp.Meta.GetNextCursor()
	}

	return &SearchAdvisoryResult{Data: data, Total: total, NextCursor: nextCursor}, nil
}
