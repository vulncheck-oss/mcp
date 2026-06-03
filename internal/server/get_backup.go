package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type getBackupArgs struct {
	Index string `json:"index" jsonschema:"Index name to get backup links for, e.g. 'vulncheck-nvd2', 'initial-access', 'vulncheck-kev'"`
}

var GetBackupTool = &mcp.Tool{
	Name:        "get_backup",
	Title:       "Get Backup",
	Description: "Return all backup links for a given index.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

func registerGetBackup(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, GetBackupTool, MakeGetBackupHandler(vc))
}

func MakeGetBackupHandler(vc client.Client) mcp.ToolHandlerFor[getBackupArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args getBackupArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.GetBackup(ctx, args.Index)
		if err != nil {
			return nil, nil, fmt.Errorf("getting backup for %q: %w", args.Index, err)
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
