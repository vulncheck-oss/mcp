package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var ListBackupsTool = &mcp.Tool{
	Name:        "list_backups",
	Title:       "List Backups",
	Description: "List all VulnCheck index backups. Call this first to discover which index names can be passed to get_backup. Accepts an optional 'search' parameter to filter results by name or description.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type listBackupsArgs struct {
	Search string `json:"search,omitempty" jsonschema:"Optional filter — return only backups whose name or description contains this string (case-insensitive)"`
}

func registerListBackups(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, ListBackupsTool, MakeListBackupsHandler(vc))
}

func MakeListBackupsHandler(vc client.Client) mcp.ToolHandlerFor[listBackupsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args listBackupsArgs) (*mcp.CallToolResult, any, error) {
		entries, err := vc.ListBackups(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing backups: %w", err)
		}

		if args.Search != "" {
			q := strings.ToLower(args.Search)
			filtered := entries[:0]
			for _, e := range entries {
				if strings.Contains(strings.ToLower(e.Name), q) || strings.Contains(strings.ToLower(e.Description), q) {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}

		out, err := json.Marshal(listEntriesResult{
			Data:  entries,
			Total: len(entries),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
