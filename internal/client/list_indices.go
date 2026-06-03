package client

import (
	"context"
	"fmt"
)

// Entry is a named item returned by list operations (indices, backups, advisories).
type Entry struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (c *VulncheckClient) ListIndices(ctx context.Context) ([]Entry, error) {
	resp, httpResp, err := c.sdk.EndpointsAPI.IndexGet(c.authContext(ctx)).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("listing indices: %w", err)
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
