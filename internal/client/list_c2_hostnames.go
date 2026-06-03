package client

import (
	"context"
	"fmt"
)

func (c *VulncheckClient) ListC2Hostnames(ctx context.Context) (string, error) {
	hostnames, httpResp, err := c.sdk.EndpointsAPI.PdnsVulncheckC2Get(c.authContext(ctx)).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return "", fmt.Errorf("listing C2 hostnames: %w", err)
	}
	return hostnames, nil
}
