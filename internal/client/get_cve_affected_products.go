package client

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// cveAffectedIndex holds the NVD documents this tool projects. It carries both
// NIST's configurations and VulnCheck's own vcConfigurations, and nist-nvd2 was
// observed to serve byte-identical content for both fields, so querying that as a
// fallback cost a round trip without adding data.
const cveAffectedIndex = "vulncheck-nvd2"

// The two configuration sets disagree on vendor strings: CVE-2024-6387 is
// openbsd/openssh to NIST and openssh/openssh to VulnCheck. Vendor/product
// de-duplication cannot collapse that, so each entry names where it came from
// rather than presenting one spelling as the answer.
const (
	sourceNVD       = "nvd"
	sourceVulnCheck = "vulncheck"
)

// maxAffectedEntries bounds each projected list. Most CVEs name a handful of
// products, but speculative-execution bugs and similar enumerate several hundred,
// and the purpose of this tool is a response that always fits in a model's context.
const maxAffectedEntries = 100

// AffectedProduct is a vendor/product pair with the version ranges a CVE applies to.
type AffectedProduct struct {
	// Part is the CPE part: "a" application, "o" operating system, "h" hardware.
	// Keeping it saves a caller inferring whether an entry is software or a device.
	Part     string   `json:"part,omitempty"`
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	Versions []string `json:"versions"`
	// Sources names the configuration sets this entry appears in, so a NIST vendor
	// spelling can be told from a VulnCheck one.
	Sources []string `json:"sources"`
}

// CVEAffectedResult projects an NVD document down to the software it names. The
// source documents reach hundreds of kilobytes; only these coordinates are returned.
type CVEAffectedResult struct {
	CVE      string            `json:"cve"`
	Products []AffectedProduct `json:"affected_products"`
	// Platforms holds entries an AND configuration marks vulnerable:false, the
	// environment a vulnerable component runs on rather than the component itself.
	// Keeping them out of Products stops the host OS being reported as the thing to
	// patch, while still answering "where does this apply".
	Platforms []AffectedProduct `json:"platforms,omitempty"`
	// The totals are always the true counts. Truncated reports whether either list
	// was cut to maxAffectedEntries, so a shortened list is never mistaken for a
	// complete one.
	TotalProducts  int  `json:"total_affected_products"`
	TotalPlatforms int  `json:"total_platforms,omitempty"`
	Truncated      bool `json:"truncated,omitempty"`
	// SkippedCriteria counts match rules that could not be parsed. A projection is
	// only worth trusting if it admits what it dropped.
	SkippedCriteria int `json:"skipped_criteria,omitempty"`
	// Note explains an empty result, so a caller can tell "nothing is affected" from
	// "this CVE carries no CPE data" - very different answers to the same question.
	Note string `json:"note,omitempty"`
}

const (
	noConfigurationsNote = "neither NIST's configurations nor VulnCheck's vcConfigurations are populated for this " +
		"CVE, so no affected products can be derived; package-ecosystem advisories (npm, PyPI, Go) commonly carry none"
	noUsableCriteriaNote = "CPE configurations are published for this CVE but none of them yielded a product; " +
		"any unparsable match rules are counted in skipped_criteria"
)

// nvdCPEMatch is one CPE match rule. NVD expresses applicability either through the
// version field of the CPE string or through the four optional range bounds.
type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// nvdNode groups match rules. NVD 2.0 nodes do not nest: an AND configuration is
// expressed as sibling nodes under one configuration, each holding one side of the
// pairing, so reading a configuration's nodes flatly covers it.
type nvdNode struct {
	// Negate inverts the node's match, so nothing under it is affirmatively affected.
	Negate   bool          `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdConfiguration struct {
	// Negate inverts the whole configuration, as above.
	Negate bool      `json:"negate"`
	Nodes  []nvdNode `json:"nodes"`
}

// nvdDocument holds both configuration sets. NIST leaves configurations unpopulated
// on CVEs it has not analysed, and for those VulnCheck's own set is usually the only
// CPE data there is, so both have to be read.
type nvdDocument struct {
	Configurations   []nvdConfiguration `json:"configurations"`
	VCConfigurations []nvdConfiguration `json:"vcConfigurations"`
}

type productKey struct {
	part    string
	vendor  string
	product string
}

// productEntry collects everything seen for one product key across both sources.
type productEntry struct {
	versions map[string]struct{}
	sources  map[string]struct{}
}

// cpeAccumulator de-duplicates match rules into vendor/product pairs. A CVE commonly
// repeats the same product across many configurations, once per platform pairing.
type cpeAccumulator struct {
	vulnerable map[productKey]*productEntry
	platforms  map[productKey]*productEntry
	skipped    int
}

func newCPEAccumulator() *cpeAccumulator {
	return &cpeAccumulator{
		vulnerable: map[productKey]*productEntry{},
		platforms:  map[productKey]*productEntry{},
	}
}

// walk records every match rule in one configuration set, attributing what it finds
// to source. Negated scopes are skipped rather than reported inverted.
func (a *cpeAccumulator) walk(configurations []nvdConfiguration, source string) {
	for _, configuration := range configurations {
		if configuration.Negate {
			continue
		}
		for _, node := range configuration.Nodes {
			if node.Negate {
				continue
			}
			for _, match := range node.CPEMatch {
				part, vendor, product, version, ok := parseCPE(match.Criteria)
				if !ok {
					a.skipped++
					continue
				}
				target := a.platforms
				if match.Vulnerable {
					target = a.vulnerable
				}
				key := productKey{part: part, vendor: vendor, product: product}
				entry := target[key]
				if entry == nil {
					entry = &productEntry{
						versions: map[string]struct{}{},
						sources:  map[string]struct{}{},
					}
					target[key] = entry
				}
				entry.versions[versionRange(match, version)] = struct{}{}
				entry.sources[source] = struct{}{}
			}
		}
	}
}

// parseCPE pulls part, vendor, product, and version out of a CPE 2.3 formatted
// string, whose fields are colon-separated as
// cpe:2.3:<part>:<vendor>:<product>:<version>:...
func parseCPE(criteria string) (part, vendor, product, version string, ok bool) {
	fields := splitCPE(criteria)
	if len(fields) < 6 {
		return "", "", "", "", false
	}
	return unescapeCPE(fields[2]), unescapeCPE(fields[3]), unescapeCPE(fields[4]), unescapeCPE(fields[5]), true
}

// splitCPE splits on the colons that separate fields, ignoring any a field escaped
// for itself. Without this an escaped colon shifts every later field by one.
func splitCPE(criteria string) []string {
	var fields []string
	start := 0
	for i := 0; i < len(criteria); i++ {
		if criteria[i] != ':' || (i > 0 && criteria[i-1] == '\\') {
			continue
		}
		fields = append(fields, criteria[start:i])
		start = i + 1
	}
	return append(fields, criteria[start:])
}

// unescapeCPE drops the backslashes CPE 2.3 requires ahead of punctuation, so a
// version reads as 15.2(5)e rather than 15.2\(5\)e. Note this is the opposite of the
// CLI's unbindValueFS, which produces the quoted well-formed name and keeps them.
func unescapeCPE(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var out strings.Builder
	out.Grow(len(field))
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+1 < len(field) {
			i++
		}
		out.WriteByte(field[i])
	}
	return out.String()
}

// versionRange renders a match rule as a readable constraint. With no range bounds
// set, the version lives in the CPE string itself, where "*" and "-" mean every
// version.
func versionRange(match nvdCPEMatch, version string) string {
	var bounds []string
	switch {
	case match.VersionStartIncluding != "":
		bounds = append(bounds, ">="+match.VersionStartIncluding)
	case match.VersionStartExcluding != "":
		bounds = append(bounds, ">"+match.VersionStartExcluding)
	}
	switch {
	case match.VersionEndIncluding != "":
		bounds = append(bounds, "<="+match.VersionEndIncluding)
	case match.VersionEndExcluding != "":
		bounds = append(bounds, "<"+match.VersionEndExcluding)
	}
	if len(bounds) > 0 {
		return strings.Join(bounds, " ")
	}
	if version == "" || version == "*" || version == "-" {
		return "all versions"
	}
	return version
}

// flatten renders the accumulator into a stably ordered slice, so the same CVE
// always projects to the same output.
func flatten(entries map[productKey]*productEntry) []AffectedProduct {
	out := make([]AffectedProduct, 0, len(entries))
	for key, entry := range entries {
		out = append(out, AffectedProduct{
			Part:     key.part,
			Vendor:   key.vendor,
			Product:  key.product,
			Versions: sortedKeys(entry.versions),
			Sources:  sortedKeys(entry.sources),
		})
	}
	slices.SortFunc(out, func(a, b AffectedProduct) int {
		if c := cmp.Compare(a.Vendor, b.Vendor); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Product, b.Product); c != 0 {
			return c
		}
		return cmp.Compare(a.Part, b.Part)
	})
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

// GetCVEAffectedProducts resolves a CVE to the software it affects by projecting the
// NVD document's CPE configurations down to vendor/product/version coordinates. The
// document itself is never returned: it is routinely large enough to exhaust a
// model's context on its own, while the coordinates it contains are small.
func (c *VulncheckClient) GetCVEAffectedProducts(ctx context.Context, cve string) (*CVEAffectedResult, error) {
	if cve == "" {
		return nil, ErrNoCVEArg
	}

	result := &CVEAffectedResult{CVE: cve, Products: []AffectedProduct{}}

	// One document carries the CVE's complete configuration set, so a limit of one
	// is sufficient.
	res, err := c.SearchIndex(ctx, SearchIndexQuery{Index: cveAffectedIndex, CVE: cve, Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("querying index %q for %s: %w", cveAffectedIndex, cve, err)
	}
	if len(res.Data) == 0 {
		result.Note = noConfigurationsNote
		return result, nil
	}

	var doc nvdDocument
	if err := json.Unmarshal(res.Data[0], &doc); err != nil {
		return nil, fmt.Errorf("decoding %q document for %s: %w", cveAffectedIndex, cve, err)
	}
	if len(doc.Configurations) == 0 && len(doc.VCConfigurations) == 0 {
		result.Note = noConfigurationsNote
		return result, nil
	}

	acc := newCPEAccumulator()
	acc.walk(doc.Configurations, sourceNVD)
	acc.walk(doc.VCConfigurations, sourceVulnCheck)

	setAffected(result, flatten(acc.vulnerable), flatten(acc.platforms), acc.skipped)
	if len(result.Products) == 0 && len(result.Platforms) == 0 {
		result.Note = noUsableCriteriaNote
	}
	return result, nil
}

// setAffected fills the result's lists and true totals, truncating each list to
// maxAffectedEntries.
func setAffected(result *CVEAffectedResult, products, platforms []AffectedProduct, skipped int) {
	result.TotalProducts = len(products)
	result.TotalPlatforms = len(platforms)
	result.SkippedCriteria = skipped
	if len(products) > maxAffectedEntries {
		products = products[:maxAffectedEntries]
		result.Truncated = true
	}
	if len(platforms) > maxAffectedEntries {
		platforms = platforms[:maxAffectedEntries]
		result.Truncated = true
	}
	result.Products = products
	result.Platforms = platforms
}
