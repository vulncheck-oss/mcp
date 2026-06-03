package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type SearchPURLsResult struct {
	Data  []vulncheck.PurlBatchVulnFinding `json:"data,omitempty"`
	Total int                              `json:"total"`
}

func (c *VulncheckClient) SearchPURLs(ctx context.Context, purls []string) (*SearchPURLsResult, error) {
	req := c.sdk.EndpointsAPI.PurlsPost(c.authContext(ctx)).RequestBody(purls)

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("searching PURLs %v: %w", purls, err)
	}

	purlResults := resp.Data
	if resp.Data == nil {
		purlResults = []vulncheck.PurlBatchVulnFinding{}
	}

	total := 0
	if resp.Meta != nil && resp.Meta.TotalDocuments != nil {
		total = int(*resp.Meta.TotalDocuments)
	}

	return &SearchPURLsResult{Data: purlResults, Total: total}, nil
}
