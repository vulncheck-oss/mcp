package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// docsFixture mirrors the shape of the published index: a title, sections that
// separate the English pages from their translations, and entries some of which carry
// no description.
const docsFixture = `# VulnCheck Docs

> Documentation for the VulnCheck API and more

## En

- [API Tokens](https://docs.vulncheck.com/raw/getting-started/api-tokens.md): All VulnCheck platform API calls require a valid API token.
- [Canary Intelligence](https://docs.vulncheck.com/raw/products/canary-intelligence.md): Exploitation data from globally deployed vulnerable hosts.
- [Query Parameters](https://docs.vulncheck.com/raw/products/canary-intelligence/query-parameters.md): Filtering canary data by CVE, country, date and IP.
- [Overview](https://docs.vulncheck.com/raw/products/target-intelligence.md)
- [Unrelated Page](https://docs.vulncheck.com/raw/misc/unrelated.md): Nothing to do with the above.

## Jp

- [APIトークン](https://docs.vulncheck.com/raw/jp/getting-started/api-tokens.md): API token page, translated.

## Kr

- [API 토큰](https://docs.vulncheck.com/raw/kr/getting-started/api-tokens.md): API token page, translated again.

## Changelog

- [2026-08-12](https://docs.vulncheck.com/raw/changelog/2026-08-12.md): Recent changes to the canary feed.
`

func docsMock(content string, err error) *mockClient {
	return &mockClient{
		searchDocsFn: func(_ context.Context) (string, error) {
			if err != nil {
				return "", err
			}
			return content, nil
		},
	}
}

func decodeDocs(t *testing.T, res *mcp.CallToolResult) searchDocsResult {
	t.Helper()
	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	var got searchDocsResult
	require.NoError(t, json.Unmarshal([]byte(text.Text), &got))
	return got
}

func TestParseDocsIndex(t *testing.T) {
	pages := parseDocsIndex(docsFixture)

	require.Len(t, pages, 8)
	assert.Equal(t, "API Tokens", pages[0].Title)
	assert.Equal(t, "https://docs.vulncheck.com/raw/getting-started/api-tokens.md", pages[0].URL)
	assert.Equal(t, "En", pages[0].Section)

	t.Run("an entry with no description still parses", func(t *testing.T) {
		var overview DocPage
		for _, p := range pages {
			if p.Title == "Overview" {
				overview = p
			}
		}
		assert.Equal(t, "En", overview.Section)
		assert.Empty(t, overview.Description)
		assert.NotEmpty(t, overview.URL)
	})

	t.Run("the document title is not treated as a section", func(t *testing.T) {
		for _, p := range pages {
			assert.NotEqual(t, "VulnCheck Docs", p.Section)
		}
	})

	t.Run("later sections are tagged", func(t *testing.T) {
		var sections []string
		for _, p := range pages {
			sections = append(sections, p.Section)
		}
		assert.Contains(t, sections, "Jp")
		assert.Contains(t, sections, "Changelog")
	})
}

// Translations restate the primary content, so including them by default would return
// the same page once per language.
func TestSearchDocs_ExcludesTranslationsByDefault(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "api tokens"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	require.NotEmpty(t, got.Data)
	assert.Equal(t, "API Tokens", got.Data[0].Title)
	for _, p := range got.Data {
		assert.NotContains(t, []string{"Jp", "Kr"}, p.Section,
			"a translated copy of the same page is not a second result")
	}
}

// Sections other than the primary one are not all translations. Restricting the search
// to the primary section would hide the changelog and the weekly reports, which are
// distinct English content.
func TestSearchDocs_SearchesEnglishSectionsBeyondThePrimaryOne(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "canary"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	var sections []string
	for _, p := range got.Data {
		sections = append(sections, p.Section)
	}
	assert.Contains(t, sections, "Changelog",
		"the changelog is its own section but is not a translation")
}

func TestIsTranslationSection(t *testing.T) {
	pages := parseDocsIndex(docsFixture)

	assert.True(t, isTranslationSection("Jp", pages), "pages sit under a matching path segment")
	assert.True(t, isTranslationSection("Kr", pages))
	assert.False(t, isTranslationSection("En", pages), "the primary section has no language segment")
	assert.False(t, isTranslationSection("Changelog", pages),
		"published under its own path segment, but not a language code")
	assert.False(t, isTranslationSection("", pages))
	assert.False(t, isTranslationSection("Nonexistent", pages))
}

func TestSearchDocs_OtherSectionsAreReachable(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "api token", Section: "Jp"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	require.NotEmpty(t, got.Data)
	assert.Equal(t, "Jp", got.Data[0].Section)
}

// A title match is a stronger signal than a passing mention in a description.
func TestSearchDocs_RanksTitleMatchesFirst(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "canary"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	require.GreaterOrEqual(t, len(got.Data), 2)
	assert.Equal(t, "Canary Intelligence", got.Data[0].Title,
		"the page whose title carries the term ranks above one that only mentions it")
}

// A specific query should not be beaten by a page that repeats one of its common words.
func TestSearchDocs_PrefersPagesMatchingEveryTerm(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "canary query parameters"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	require.NotEmpty(t, got.Data)
	assert.Equal(t, "Query Parameters", got.Data[0].Title)
}

// The path names the product even where the title is generic, such as "Overview".
func TestSearchDocs_MatchesOnThePagePath(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "target-intelligence"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	require.NotEmpty(t, got.Data)
	assert.Equal(t, "Overview", got.Data[0].Title)
}

func TestSearchDocs_NoQueryListsSections(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	assert.Empty(t, got.Data, "listing every page is what this change exists to avoid")
	assert.Equal(t, []SectionCount{
		{Section: "En", Pages: 5},
		{Section: "Jp", Pages: 1, Translation: true},
		{Section: "Kr", Pages: 1, Translation: true},
		{Section: "Changelog", Pages: 1},
	}, got.Sections,
		"sections are reported in order with their sizes, and translations are marked so their "+
			"exclusion from a default search is explicable")
	assert.Contains(t, strings.Join(got.Notes, " "), "no query")
}

func TestSearchDocs_ReportsNoMatchExplicitly(t *testing.T) {
	res, _, err := MakeSearchDocsHandler(docsMock(docsFixture, nil))(
		context.Background(), nil, searchDocsArgs{Query: "kubernetes helm chart"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	assert.Empty(t, got.Data)
	assert.Zero(t, got.Matched)
	assert.Contains(t, strings.Join(got.Notes, " "), "nothing matched")
}

func TestSearchDocs_ReportsWhenMoreMatchedThanShown(t *testing.T) {
	var b strings.Builder
	b.WriteString("## En\n")
	for i := range maxDocsResults + 5 {
		b.WriteString("- [Canary Page ")
		b.WriteByte(byte('a' + i))
		b.WriteString("](https://docs.vulncheck.com/raw/p")
		b.WriteByte(byte('a' + i))
		b.WriteString(".md): canary detail\n")
	}

	res, _, err := MakeSearchDocsHandler(docsMock(b.String(), nil))(
		context.Background(), nil, searchDocsArgs{Query: "canary"})
	require.NoError(t, err)

	got := decodeDocs(t, res)
	assert.Len(t, got.Data, maxDocsResults)
	assert.Equal(t, maxDocsResults, got.Returned)
	assert.Equal(t, maxDocsResults+5, got.Matched, "the caller is told how much it did not see")
	assert.Contains(t, strings.Join(got.Notes, " "), "narrow the query")
}

func TestDocsQueryTerms_DropsWordsThatCannotNarrow(t *testing.T) {
	assert.Equal(t, []string{"filter", "canaries", "country"},
		docsQueryTerms("How do I filter canaries by country?"))

	t.Run("a query of only common words keeps them rather than matching nothing", func(t *testing.T) {
		assert.Equal(t, []string{"how", "do", "i"}, docsQueryTerms("how do i"))
	})
}

func TestSearchDocs_PropagatesClientErrors(t *testing.T) {
	_, _, err := MakeSearchDocsHandler(docsMock("", errors.New("connection refused")))(
		context.Background(), nil, searchDocsArgs{Query: "anything"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docs index")
}
