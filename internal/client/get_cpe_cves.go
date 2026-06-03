package client

import (
	"context"
	"fmt"
)

type CPECVEsResult struct {
	CVEs  []string `json:"cves"`
	Total int      `json:"total"`
}

func (c *VulncheckClient) GetCPECVEs(ctx context.Context, cpe string, vulnerableOnly bool) (*CPECVEsResult, error) {
	req := c.sdk.EndpointsAPI.CpeGet(c.authContext(ctx)).Cpe(cpe)
	if vulnerableOnly {
		req = req.IsVulnerable("true")
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("getting CPE CVEs for %q: %w", cpe, err)
	}

	cves := resp.Data
	if cves == nil {
		cves = []string{}
	}

	total := 0
	if resp.Meta != nil && resp.Meta.TotalDocuments != nil {
		total = int(*resp.Meta.TotalDocuments)
	}

	return &CPECVEsResult{CVEs: cves, Total: total}, nil
}
