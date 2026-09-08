package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
)

// IndexQueryResult holds the parsed response from a /v3/index/{name} query.
type IndexQueryResult struct {
	Data       []json.RawMessage `json:"data"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Total      int               `json:"total"`

	// FiltersSent are the filter parameters this query actually put on the request, in
	// upstream spelling. Control parameters — sort, order, limit, cursor — are excluded:
	// the index does not list them among what it accepts, so including them here would
	// make every sorted query look like it had a filter dropped.
	FiltersSent []string `json:"-"`

	// FiltersAccepted is the index's own account of what it accepts, read from
	// _meta.parameters. Empty means the index did not say, which is not the same as
	// accepting nothing — see indexResponseMeta.Parameters.
	FiltersAccepted []string `json:"-"`

	// CursorContinuation records whether this query resumed a walk, which NextCursor
	// alone cannot say: a plain query returns an empty next_cursor too, so without this
	// an ordinary empty page is indistinguishable from an exhausted walk.
	//
	// Deliberately not set by start_cursor. A first call has walked nothing, so an empty
	// first page proves only that this page is empty — and announcing the walk complete
	// there would replace advice that might work ("retry with a larger limit") with
	// advice that cannot.
	CursorContinuation bool `json:"-"`
}

type SearchIndexQuery struct {
	Index              string
	CVE                string
	Cursor             string
	Limit              int
	StartCursor        bool
	LastModStartDate   string
	LastModEndDate     string
	PubStartDate       string
	PubEndDate         string
	UpdatedAtStartDate string
	UpdatedAtEndDate   string
	Date               string
	Alias              string
	IAVA               string
	Sort               string
	Order              string

	// Index-specific filters. Indices accept different subsets of these, so only
	// send the ones the target index supports.

	// IP Intelligence and Target Intelligence
	ASN         string
	CIDR        string
	Country     string
	CountryCode string
	Hostname    string

	// IP Intelligence
	ID   string
	Kind string

	// Canary Intelligence
	SrcCountry string
	DstCountry string
	SrcIP      string
	SrcASN     string

	// Target Intelligence
	Vendor          string
	Product         string
	Version         string
	CPE             string
	Protocol        string
	Transport       string
	Port            int
	Domain          string
	Classifications string
	ContainsCVE     *bool

	// Threat intelligence, valid on the vulnerability and exploit indices and on
	// the ipintel family
	ThreatActor string
	MitreID     string
	MispID      string
	Ransomware  string
	Botnet      string

	// JVNDB is the Japanese vulnerability database identifier, e.g.
	// "JVNDB-2025-007355".
	JVNDB string

	// Exploit curation filters. Validated upstream as closed vocabularies, so an
	// unrecognised value is rejected rather than ignored.
	MaxExploitMaturity string
	ValidationLevel    string

	// InKEV and InVCKEV are tri-state: false selects records explicitly marked false,
	// which is not necessarily the complement of true, so an unset filter is omitted.
	InKEV   *bool
	InVCKEV *bool
}

type indexResponseMeta struct {
	TotalDocuments int    `json:"total_documents"`
	NextCursor     string `json:"next_cursor,omitempty"`

	// Parameters is the index's own list of the query parameters it accepts, returned
	// inline with every query. It is the authoritative account of what this index can be
	// filtered by, and it arrives free: no second request is needed to learn it.
	//
	// It can be absent on a zero-row response, so an empty list means "unknown" rather
	// than "accepts nothing". Which zero-row responses carry it is not a property of the
	// index: vulncheck-nvd2 publishes all 19 of its parameters for a cve that matches
	// nothing and none for an unmatched threat_actor, though it accepts both. Every index
	// sampled publishes it on a non-empty response, cursor pages included.
	Parameters []struct {
		Name string `json:"name"`
	} `json:"parameters,omitempty"`
}

type indexResponse struct {
	Meta indexResponseMeta `json:"_meta"`
	Data json.RawMessage   `json:"data"`
}

func (c *VulncheckClient) SearchIndex(ctx context.Context, q SearchIndexQuery) (*IndexQueryResult, error) {
	if q.Index == "" {
		return nil, ErrNoIndexArg
	}

	u, err := url.Parse(c.baseURL + "/v3/index/" + url.PathEscape(q.Index))
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}

	// filtersSent records which filter parameters actually went on the request, in the
	// upstream spelling, so a caller can compare them against what the index says it
	// accepts. Recording it here rather than deriving it from the tool's arguments means
	// it cannot drift from the query actually sent, and it needs no arg-name translation.
	//
	// Only filters go in. sort and order steer the request rather than narrow it and are
	// not advertised in _meta.parameters, so counting them would report a dropped filter
	// on every sorted query; they are set below, outside this map, for that reason. limit,
	// page and cursor never reach here at all.
	var filtersSent []string
	sent := func(key string) {
		filtersSent = append(filtersSent, key)
	}

	p := u.Query()
	for key, value := range map[string]string{
		"cve":                  q.CVE,
		"alias":                q.Alias,
		"iava":                 q.IAVA,
		"lastModStartDate":     q.LastModStartDate,
		"lastModEndDate":       q.LastModEndDate,
		"pubStartDate":         q.PubStartDate,
		"pubEndDate":           q.PubEndDate,
		"updatedAtStartDate":   q.UpdatedAtStartDate,
		"updatedAtEndDate":     q.UpdatedAtEndDate,
		"date":                 q.Date,
		"asn":                  q.ASN,
		"cidr":                 q.CIDR,
		"country":              q.Country,
		"country_code":         q.CountryCode,
		"hostname":             q.Hostname,
		"id":                   q.ID,
		"kind":                 q.Kind,
		"src_country":          q.SrcCountry,
		"dst_country":          q.DstCountry,
		"src_ip":               q.SrcIP,
		"src_asn":              q.SrcASN,
		"vendor":               q.Vendor,
		"product":              q.Product,
		"version":              q.Version,
		"cpe":                  q.CPE,
		"protocol":             q.Protocol,
		"transport":            q.Transport,
		"domain":               q.Domain,
		"classifications":      q.Classifications,
		"threat_actor":         q.ThreatActor,
		"mitre_id":             q.MitreID,
		"misp_id":              q.MispID,
		"ransomware":           q.Ransomware,
		"botnet":               q.Botnet,
		"jvndb":                q.JVNDB,
		"max_exploit_maturity": q.MaxExploitMaturity,
		"validation_level":     q.ValidationLevel,
	} {
		if value != "" {
			p.Set(key, value)
			sent(key)
		}
	}
	// Controls, not filters: set outside the map above so they are never recorded as
	// filters sent.
	if q.Sort != "" {
		p.Set("sort", q.Sort)
	}
	if q.Order != "" {
		p.Set("order", q.Order)
	}

	if q.Port > 0 {
		p.Set("port", strconv.Itoa(q.Port))
		sent("port")
	}
	// contains_cve=false is a meaningful filter (hosts with no associated CVE), so
	// it is only omitted when the caller left it unset.
	if q.ContainsCVE != nil {
		p.Set("contains_cve", strconv.FormatBool(*q.ContainsCVE))
		sent("contains_cve")
	}
	if q.InKEV != nil {
		p.Set("in_kev", strconv.FormatBool(*q.InKEV))
		sent("in_kev")
	}
	if q.InVCKEV != nil {
		p.Set("in_vckev", strconv.FormatBool(*q.InVCKEV))
		sent("in_vckev")
	}
	if q.Cursor != "" {
		p.Set("cursor", q.Cursor)
	} else if q.StartCursor {
		p.Set("start_cursor", "true")
	}
	if q.Limit > 0 {
		p.Set("limit", strconv.Itoa(q.Limit))
	}
	u.RawQuery = p.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req) //nolint:gosec // G704: baseURL is trusted config; index name is path-escaped
	if err != nil {
		return nil, fmt.Errorf("querying index %q: %w", q.Index, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("index %q: HTTP %d: %s", q.Index, resp.StatusCode, body)
	}

	var envelope indexResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	var items []json.RawMessage
	if envelope.Data != nil {
		if err := json.Unmarshal(envelope.Data, &items); err != nil {
			return nil, fmt.Errorf("decoding data array: %w", err)
		}
	}
	if items == nil {
		items = []json.RawMessage{}
	}

	// Sorted so the same query always reports the same order, and deduped because at
	// least one index (vulncheck-nvd2) lists a parameter twice.
	slices.Sort(filtersSent)
	accepted := make([]string, 0, len(envelope.Meta.Parameters))
	for _, param := range envelope.Meta.Parameters {
		// Skipped as describe_index skips them; an empty list means "the index did not
		// say", and one blank entry would falsely make it look like it did.
		if param.Name == "" {
			continue
		}
		accepted = append(accepted, param.Name)
	}
	slices.Sort(accepted)

	return &IndexQueryResult{
		Data:               items,
		NextCursor:         envelope.Meta.NextCursor,
		Total:              envelope.Meta.TotalDocuments,
		FiltersSent:        filtersSent,
		FiltersAccepted:    slices.Compact(accepted),
		CursorContinuation: q.Cursor != "",
	}, nil
}
