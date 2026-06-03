package client

import (
	"context"
	"fmt"
)

func (c *VulncheckClient) GetRules(ctx context.Context, ruleType string) (string, error) {
	rules, httpResp, err := c.sdk.EndpointsAPI.RulesInitialAccessTypeGet(c.authContext(ctx), ruleType).Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return "", fmt.Errorf("getting %q rules: %w", ruleType, err)
	}
	return rules, nil
}
