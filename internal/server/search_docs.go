package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

type searchDocsArgs struct {
	Query   string `json:"query,omitempty"   jsonschema:"What to look for, e.g. 'filter canaries by country' or 'api tokens'. Matched against page titles, descriptions and paths. Omit to list the available documentation sections instead"`
	Section string `json:"section,omitempty" jsonschema:"Restrict the search to one documentation section. By default every section is searched except translations of the primary content, which would otherwise return each result once per language. Call without a query to see the sections"`
}

var SearchDocsTool = &mcp.Tool{
	Name:  "search_docs",
	Title: "Search Docs",
	Description: "Search the VulnCheck documentation and return the pages that match, ranked by relevance. " +
		"Returns titles, descriptions and URLs — pass a URL to get_doc for the page itself. " +
		"Searches all sections by default, except translations of the primary content. Call without a query to list the sections.",
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	},
}

// searchDocsResult carries the pages under the shared envelope.
//
// It was the last list-returning tool outside that contract, reporting its match count as
// `matched`. The distinction was imagined: `total` means how many matched upstream and
// `returned` how many are present, which is exactly what this tool has. It does not
// paginate, so it never carries a cursor, and it searches a locally-parsed index rather
// than API records, so it stays outside capResult and the byte budget.
type searchDocsResult struct {
	envelope
	Query    string         `json:"query,omitempty"`
	Section  string         `json:"section,omitempty"`
	Sections []SectionCount `json:"sections,omitempty"`
	Data     []DocPage      `json:"data"`
}

const (
	docsBrowseNote = "no query was given, so this lists the documentation sections rather than every " +
		"page in them. Search within one by passing a query"

	docsTruncatedNote = "more pages matched than are shown, ranked by relevance — narrow the query " +
		"rather than asking again, since there is no pagination here"

	docsNoMatchNote = "nothing matched. Try fewer or more general terms, or call without a query to " +
		"see which sections exist"
)

func registerSearchDocs(srv *mcp.Server, vc client.Client) {
	mcp.AddTool(srv, SearchDocsTool, MakeSearchDocsHandler(vc))
}

func MakeSearchDocsHandler(vc client.Client) mcp.ToolHandlerFor[searchDocsArgs, any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchDocsArgs) (*mcp.CallToolResult, any, error) {
		raw, err := vc.SearchDocs(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching docs index: %w", err)
		}

		pages := parseDocsIndex(raw)
		// Data starts as an empty slice, not nil, and carries no omitempty: a search
		// matching nothing must return `data: []` rather than drop the field, or "no
		// pages matched" is indistinguishable from a malfunction. omitempty elides an
		// empty slice as readily as a nil one, so the tag had to go for the count to
		// mean anything. Browse mode answers with sections and legitimately has no
		// pages, which `data: []` states plainly alongside the note explaining why.
		result := searchDocsResult{Query: args.Query, Data: []DocPage{}}

		if args.Query == "" {
			// Returning every page here would cost a large share of the caller's context
			// to answer a question it has not asked yet.
			result.Sections = annotateTranslations(pages)
			result.Notes = append(result.Notes, docsBrowseNote)
		} else {
			result.Section = args.Section

			matches, total := searchDocsIndex(pages, args.Query, args.Section)
			result.Data = matches
			result.Returned = len(matches)
			result.Total = total

			switch {
			case total == 0:
				result.Notes = append(result.Notes, docsNoMatchNote)
			case total > len(matches):
				result.Notes = append(result.Notes, docsTruncatedNote)
			}
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
