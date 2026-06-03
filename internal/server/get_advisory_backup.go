package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getAdvisoryBackupArgs struct {
	Name string `json:"name" jsonschema:"Advisory feed name, e.g. 'ghsa' — use v4_list_advisory_backups to discover valid names"`
}

var GetAdvisoryBackupTool = &mcp.Tool{
	Name:        "v4_get_advisory_backup",
	Title:       "Get Advisory Backup",
	Description: "Return pre-signed download URLs for a VulnCheck v4 advisory feed backup.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerGetAdvisoryBackup(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, GetAdvisoryBackupTool, MakeGetAdvisoryBackupHandler(vc))
}

func MakeGetAdvisoryBackupHandler(vc client.Client) mcp.ToolHandlerFor[getAdvisoryBackupArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args getAdvisoryBackupArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.GetAdvisoryBackup(ctx, args.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("getting advisory backup for %q: %w", args.Name, err)
		}

		out, err := json.Marshal(result)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
