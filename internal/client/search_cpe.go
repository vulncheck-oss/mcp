package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type SearchCPEQuery struct {
	Part           string
	Vendor         string
	Product        string
	Version        string
	VulnerableOnly bool
}

type SearchCPEResult struct {
	Data  []vulncheck.SearchResponseDataOut `json:"data"`
	Total int                               `json:"total"`
}

func (c *VulncheckClient) SearchCPE(ctx context.Context, q SearchCPEQuery) (*SearchCPEResult, error) {
	req := c.sdk.EndpointsAPI.SearchCpeGet(c.authContext(ctx))
	if q.Part != "" {
		req = req.Part(q.Part)
	}
	if q.Vendor != "" {
		req = req.Vendor(q.Vendor)
	}
	if q.Product != "" {
		req = req.Product(q.Product)
	}
	if q.Version != "" {
		req = req.Version(q.Version)
	}
	if q.VulnerableOnly {
		req = req.IsVulnerable("true")
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("searching CPE: %w", err)
	}

	data := resp.Data
	if data == nil {
		data = []vulncheck.SearchResponseDataOut{}
	}

	total := 0
	if resp.Meta != nil && resp.Meta.TotalDocuments != nil {
		total = int(*resp.Meta.TotalDocuments)
	}

	return &SearchCPEResult{Data: data, Total: total}, nil
}
