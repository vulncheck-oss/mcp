package client

import (
	"context"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

// GetBackupResult holds the links for a given index backup.
type GetBackupResult struct {
	Index string                        `json:"index"`
	Data  []vulncheck.ParamsIndexBackup `json:"data"`
}

func (c *VulncheckClient) GetBackup(ctx context.Context, index string) (*GetBackupResult, error) {
	if index == "" {
		return nil, ErrNoIndexArg
	}

	req := c.sdk.EndpointsAPI.BackupIndexGet(c.authContext(ctx), index)

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("getting backup for %q: %w", index, err)
	}

	return &GetBackupResult{
		Index: index,
		Data:  resp.Data,
	}, nil
}
