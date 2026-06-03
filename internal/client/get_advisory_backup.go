package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func (c *VulncheckClient) GetAdvisoryBackup(ctx context.Context, name string) (*vulncheck.BackupBackupResponse, error) {
	resp, httpResp, err := c.sdk.BackupAPI.V4GetBackupByName(c.authContext(ctx), name).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("getting advisory backup for %q: %w", name, err)
	}
	return resp, nil
}
