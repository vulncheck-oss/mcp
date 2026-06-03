package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type listAdvisoryBackupsResult struct {
	Data  []vulncheck.BackupFeedItem `json:"data"`
	Total int                        `json:"total"`
}

var ListAdvisoryBackupsTool = &mcp.Tool{
	Name:        "v4_list_advisory_backups",
	Title:       "List Advisory Backups",
	Description: "List all VulnCheck v4 advisory backup feeds and their availability. Call this first to discover which feed names can be passed to v4_get_advisory_backup.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerListAdvisoryBackups(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListAdvisoryBackupsTool, MakeListAdvisoryBackupsHandler(vc))
}

func MakeListAdvisoryBackupsHandler(vc client.Client) mcp.ToolHandlerFor[struct{}, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		entries, err := vc.ListAdvisoryBackups(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing advisory backups: %w", err)
		}

		out, err := json.Marshal(listAdvisoryBackupsResult{Data: entries, Total: len(entries)})
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
