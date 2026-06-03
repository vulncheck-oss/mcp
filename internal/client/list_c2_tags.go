package client

import (
	"context"
	"fmt"
)

func (c *VulncheckClient) ListC2Tags(ctx context.Context) (string, error) {
	tags, httpResp, err := c.sdk.EndpointsAPI.TagsVulncheckC2Get(c.authContext(ctx)).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return "", fmt.Errorf("listing C2 tags: %w", err)
	}
	return tags, nil
}
