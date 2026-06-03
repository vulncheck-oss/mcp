package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func (c *VulncheckClient) ListAdvisoryBackups(ctx context.Context) ([]vulncheck.BackupFeedItem, error) {
	resp, httpResp, err := c.sdk.BackupAPI.V4ListBackups(c.authContext(ctx)).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("listing advisory backups: %w", err)
	}

	data := resp.Data
	if data == nil {
		data = []vulncheck.BackupFeedItem{}
	}
	return data, nil
}
