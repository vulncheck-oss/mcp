package client

import (
	"context"
	"fmt"
)

func (c *VulncheckClient) ListBackups(ctx context.Context) ([]Entry, error) {
	resp, httpResp, err := c.sdk.EndpointsAPI.BackupGet(c.authContext(ctx)).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("listing backups: %w", err)
	}

	entries := make([]Entry, 0, len(resp.Data))
	for _, p := range resp.Data {
		e := Entry{}
		if p.Name != nil {
			e.Name = *p.Name
		}
		if p.Description != nil {
			e.Description = *p.Description
		}
		entries = append(entries, e)
	}
	return entries, nil
}
