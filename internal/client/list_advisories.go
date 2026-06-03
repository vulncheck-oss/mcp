package client

import (
	"context"
	"fmt"
)

func (c *VulncheckClient) ListAdvisories(ctx context.Context) ([]Entry, error) {
	resp, httpResp, err := c.sdk.AdvisoryAPI.V4ListAdvisoryFeeds(c.authContext(ctx)).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("listing advisories: %w", err)
	}

	entries := make([]Entry, 0, len(resp.Data))
	for _, item := range resp.Data {
		e := Entry{}
		if item.Name != nil {
			e.Name = *item.Name
		}
		if item.Description != nil {
			e.Description = *item.Description
		}
		entries = append(entries, e)
	}
	return entries, nil
}
