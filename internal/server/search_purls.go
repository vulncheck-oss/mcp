package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchPURLsArgs struct {
	PURLs []string `json:"purls" jsonschema:"Package URLs including a version, e.g. 'pkg:npm/@openai/codex@0.30.0' — the API returns findings only for fully versioned PURLs"`
}

var SearchPURLsTool = &mcp.Tool{
	Name:  "search_purls",
	Title: "Search Package URLs",
	Description: "Return vulnerability findings for one or more Package URLs (PURLs). Each result includes associated CVEs and vulnerability details. " +
		"PURLs must include a version (e.g. 'pkg:npm/@openai/codex@0.30.0'): the API silently returns no findings for a versionless PURL. " +
		"For version-agnostic discovery use v4_search_advisory with package_name instead.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// searchPURLsResponse wraps the client result so the handler can flag versionless
// PURLs in-band: the backend answers them with an empty result, which otherwise
// reads as "no known vulnerabilities".
type searchPURLsResponse struct {
	*client.SearchPURLsResult
	Note string `json:"note,omitempty"`
}

// purlLacksVersion reports whether a PURL names no version. The version follows an
// "@" after the final path segment (a namespace such as "@openai" also starts with
// "@", so earlier segments cannot be trusted).
func purlLacksVersion(purl string) bool {
	// Qualifiers and subpath follow the version and may themselves contain "/".
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	last := purl[strings.LastIndex(purl, "/")+1:]
	return !strings.Contains(last, "@")
}

func registerSearchPURLs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchPURLsTool, MakeSearchPURLsHandler(vc))
}

func MakeSearchPURLsHandler(vc client.Client) mcp.ToolHandlerFor[searchPURLsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchPURLsArgs) (*mcp.CallToolResult, any, error) {
		result, err := vc.SearchPURLs(ctx, args.PURLs)
		if err != nil {
			return nil, nil, fmt.Errorf("searching PURLs: %w", err)
		}

		response := searchPURLsResponse{SearchPURLsResult: result}
		var versionless []string
		for _, purl := range args.PURLs {
			if purlLacksVersion(purl) {
				versionless = append(versionless, purl)
			}
		}
		if len(versionless) > 0 {
			response.Note = fmt.Sprintf(
				"no findings are ever returned for PURLs without a version: %s — append a version "+
					"(e.g. 'pkg:npm/@openai/codex@0.30.0') or use v4_search_advisory with package_name "+
					"for version-agnostic discovery; an empty result here does not mean the package has no known vulnerabilities",
				strings.Join(versionless, ", "))
		}

		out, err := json.Marshal(response)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing results: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
		}, nil, nil
	}
}
