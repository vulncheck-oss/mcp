package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

// dedicatedTools maps an index to the tool that wraps it. Where one exists it exposes
// filters search_index does not, so a caller asking what an index supports should be
// sent there rather than left to compose the generic tool.
var dedicatedTools = map[string]string{
	targetIntelIndex: "search_target_intel",
	canaryPrefix:     "search_canaries",
}

func init() {
	for _, w := range indexWindows {
		dedicatedTools[ipIntelPrefix+"-"+w] = "search_ip_intel"
		dedicatedTools[canaryPrefix+"-"+w] = "search_canaries"
	}
}

type describeIndexArgs struct {
	Index string `json:"index" jsonschema:"Index name to describe, e.g. 'vulncheck-nvd2'. Use list_indices to discover names"`
}

var DescribeIndexTool = &mcp.Tool{
	Name:  "describe_index",
	Title: "Describe Index",
	Description: "Report which filters an index accepts, how large it is, and which tool to use for it. " +
		"Call this before search_index against an unfamiliar index: indices accept different filters, and one an index does not support has no effect rather than raising an error, so a query can appear to filter when it does not. " +
		"Filters are read from the index itself, so the list reflects what it currently supports.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

type describeIndexResult struct {
	*client.IndexDescription

	// Tool names the dedicated tool for this index when one exists, so the answer to
	// "how do I query this" comes back with the answer to "what can I filter on".
	Tool string `json:"tool,omitempty"`

	// SupportedByTool lists the filters the named tool can send, which is a subset of
	// what the index advertises.
	SupportedByTool []string `json:"supported_by_tool,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

const (
	dedicatedToolNote = "this index has a dedicated tool, listed in tool, which exposes filters " +
		"search_index does not — prefer it"

	genericToolNote = "query this index with search_index. It sends the filters common to every " +
		"index, so a filter listed here that search_index has no argument for cannot be sent"
)

func registerDescribeIndex(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, DescribeIndexTool, MakeDescribeIndexHandler(vc))
}

func MakeDescribeIndexHandler(vc client.Client) mcp.ToolHandlerFor[describeIndexArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args describeIndexArgs) (*mcp.CallToolResult, any, error) {
		description, err := vc.DescribeIndex(ctx, args.Index)
		if err != nil {
			return nil, nil, fmt.Errorf("describing index: %w", err)
		}

		result := describeIndexResult{IndexDescription: description}
		if tool, ok := dedicatedTools[args.Index]; ok {
			result.Tool = tool
			result.Notes = append(result.Notes, dedicatedToolNote)
		} else {
			result.Tool = "search_index"
			result.SupportedByTool = intersect(description.Filters, searchIndexFilters)
			result.Notes = append(result.Notes, genericToolNote)
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

// intersect keeps the members of advertised that the tool can actually send,
// preserving the index's own ordering.
func intersect(advertised []string, supported map[string]bool) []string {
	out := make([]string, 0, len(advertised))
	for _, f := range advertised {
		if supported[f] {
			out = append(out, f)
		}
	}
	return out
}
