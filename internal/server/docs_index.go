package server

import (
	"regexp"
	"sort"
	"strings"
)

// The documentation index is published as a flat list of pages, one per line, in the
// form "- [Title](url): description", grouped under headings that separate the
// English pages from their translations and from the changelog.
//
// There is no search endpoint for it, so searching means parsing that list and
// scoring it here. The alternative — returning the whole index and leaving the caller
// to read it — costs a large share of a context window to answer one question.
var (
	docsHeading = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*$`)
	docsEntry   = regexp.MustCompile(`^-\s+\[([^\]]+)\]\(([^)]+)\)(?::\s*(.*))?$`)
)

// Some sections are translations of the English pages rather than distinct content,
// so by default they are left out: including them returns each result several times
// over in languages the caller did not ask for. Other sections carry their own
// English content and must not be excluded — narrowing to the primary section alone
// would hide the changelog and the weekly intelligence reports entirely.
//
// A section is taken to be a translation when its name is a two-letter language code
// and its pages live under a matching path segment. Both conditions are needed: the
// path test alone would catch any section published under its own name, such as the
// changelog, and the name test alone would catch the primary section. Detecting it
// this way means a language added later is excluded without a code change.
func isTranslationSection(section string, pages []DocPage) bool {
	if !isLanguageCode(section) {
		return false
	}
	prefix := "/raw/" + strings.ToLower(section) + "/"
	seen, under := 0, 0
	for _, p := range pages {
		if p.Section != section {
			continue
		}
		seen++
		if strings.Contains(strings.ToLower(p.URL), prefix) {
			under++
		}
	}
	return seen > 0 && under*2 > seen
}

// isLanguageCode reports whether a section name looks like a two-letter language code.
func isLanguageCode(section string) bool {
	if len(section) != 2 {
		return false
	}
	for _, r := range strings.ToLower(section) {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// translationSections reports which sections are translations of the primary content.
func translationSections(pages []DocPage) map[string]bool {
	out := map[string]bool{}
	for _, sc := range docsSectionCounts(pages) {
		if isTranslationSection(sc.Section, pages) {
			out[sc.Section] = true
		}
	}
	return out
}

// maxDocsResults bounds a search response. Ten pages is more than enough to choose
// from, and the count of matches is reported separately so a caller can tell when it
// should narrow instead of paginate.
const maxDocsResults = 10

// DocPage is one page in the documentation index.
type DocPage struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	Section     string `json:"section,omitempty"`
}

// parseDocsIndex reads the published index into pages, tagging each with the heading
// it appeared under. Lines that are neither a heading nor an entry are skipped, so a
// change to the surrounding prose does not break parsing.
func parseDocsIndex(raw string) []DocPage {
	var pages []DocPage
	section := ""

	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if m := docsHeading.FindStringSubmatch(trimmed); m != nil {
			// The document title is a single-hash heading above any section, so it is
			// only treated as a section when it is nested.
			if strings.HasPrefix(trimmed, "##") {
				section = m[1]
			}
			continue
		}
		if m := docsEntry.FindStringSubmatch(trimmed); m != nil {
			pages = append(pages, DocPage{
				Title:       strings.TrimSpace(m[1]),
				URL:         strings.TrimSpace(m[2]),
				Description: strings.TrimSpace(m[3]),
				Section:     section,
			})
		}
	}
	return pages
}

// docsSectionCounts reports how many pages each section holds, in the order the
// sections appear, so a caller with no query can see what exists before searching.
//
// It does not mark translations, because the check for those calls this — see
// annotateTranslations for the caller-facing version.
func docsSectionCounts(pages []DocPage) []SectionCount {
	var order []string
	counts := map[string]int{}
	for _, p := range pages {
		if _, seen := counts[p.Section]; !seen {
			order = append(order, p.Section)
		}
		counts[p.Section]++
	}
	out := make([]SectionCount, 0, len(order))
	for _, s := range order {
		out = append(out, SectionCount{Section: s, Pages: counts[s]})
	}
	return out
}

// SectionCount is one section of the documentation and its size.
type SectionCount struct {
	Section string `json:"section"`
	Pages   int    `json:"pages"`

	// Translation marks a section that restates the primary content in another
	// language. Those are excluded from a search unless named explicitly, so saying
	// which they are explains an otherwise surprising omission.
	Translation bool `json:"translation,omitempty"`
}

// annotateTranslations returns the section counts with translations marked.
func annotateTranslations(pages []DocPage) []SectionCount {
	counts := docsSectionCounts(pages)
	for i := range counts {
		counts[i].Translation = isTranslationSection(counts[i].Section, pages)
	}
	return counts
}

// scoredPage carries a page with its relevance, kept separate so the score does not
// reach the caller — it is an implementation detail of the ranking, not information
// a caller can act on.
type scoredPage struct {
	page    DocPage
	score   int
	matched int
}

// searchDocsIndex ranks pages against the query terms.
//
// Titles are weighted above descriptions because a page whose title carries the term
// is usually about it, whereas a description may only mention it in passing. Pages
// matching every term rank above pages matching some, so an unusually specific query
// does not get swamped by entries that happen to repeat one common word.
// An empty section searches every section that is not a translation. Naming a section
// searches only that one, including a translation if that is what was asked for.
func searchDocsIndex(pages []DocPage, query, section string) ([]DocPage, int) {
	terms := docsQueryTerms(query)
	if len(terms) == 0 {
		return nil, 0
	}

	translations := map[string]bool{}
	if section == "" {
		translations = translationSections(pages)
	}

	var scored []scoredPage
	for _, p := range pages {
		if section != "" && !strings.EqualFold(p.Section, section) {
			continue
		}
		if translations[p.Section] {
			continue
		}
		title := strings.ToLower(p.Title)
		desc := strings.ToLower(p.Description)
		urlPath := strings.ToLower(p.URL)

		score, matched := 0, 0
		for _, t := range terms {
			hit := false
			if strings.Contains(title, t) {
				score += 10
				hit = true
			}
			if strings.Contains(desc, t) {
				score += 3
				hit = true
			}
			// The URL carries the page's path, which names the product or endpoint even
			// when the title is generic, such as a page called "Overview".
			if strings.Contains(urlPath, t) {
				score += 2
				hit = true
			}
			if hit {
				matched++
			}
		}
		if matched > 0 {
			scored = append(scored, scoredPage{page: p, score: score, matched: matched})
		}
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].matched != scored[j].matched {
			return scored[i].matched > scored[j].matched
		}
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].page.Title < scored[j].page.Title
	})

	total := len(scored)
	if len(scored) > maxDocsResults {
		scored = scored[:maxDocsResults]
	}
	out := make([]DocPage, 0, len(scored))
	for _, s := range scored {
		out = append(out, s.page)
	}
	return out, total
}

// docsStopWords are terms too common in a documentation question to discriminate
// between pages. Left in, a question phrased as a sentence scores every page that
// happens to contain "the".
var docsStopWords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "by": true, "can": true, "do": true, "does": true, "for": true,
	"from": true, "how": true, "i": true, "in": true, "is": true, "it": true,
	"me": true, "my": true, "of": true, "on": true, "or": true, "the": true,
	"to": true, "what": true, "when": true, "where": true, "which": true,
	"with": true, "you": true,
}

// docsQueryTerms splits a query into comparable terms, dropping punctuation and words
// too common to narrow anything. A query made entirely of stop words keeps them,
// since returning nothing would be less useful than returning a weak match.
func docsQueryTerms(query string) []string {
	fields := strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		letter := 'a' <= r && r <= 'z'
		digit := '0' <= r && r <= '9'
		return !letter && !digit && r != '-' && r != '_'
	})

	terms := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < 2 || docsStopWords[f] {
			continue
		}
		terms = append(terms, f)
	}
	if len(terms) == 0 {
		return fields
	}
	return terms
}
