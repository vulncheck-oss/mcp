package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// IndexQueryResult holds the parsed response from a /v3/index/{name} query.
type IndexQueryResult struct {
	Data       []json.RawMessage `json:"data"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Total      int               `json:"total"`
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
}

type indexResponseMeta struct {
	TotalDocuments int    `json:"total_documents"`
	NextCursor     string `json:"next_cursor,omitempty"`
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

	p := u.Query()
	for key, value := range map[string]string{
		"cve":                q.CVE,
		"alias":              q.Alias,
		"iava":               q.IAVA,
		"lastModStartDate":   q.LastModStartDate,
		"lastModEndDate":     q.LastModEndDate,
		"pubStartDate":       q.PubStartDate,
		"pubEndDate":         q.PubEndDate,
		"updatedAtStartDate": q.UpdatedAtStartDate,
		"updatedAtEndDate":   q.UpdatedAtEndDate,
		"date":               q.Date,
		"sort":               q.Sort,
		"order":              q.Order,
		"asn":                q.ASN,
		"cidr":               q.CIDR,
		"country":            q.Country,
		"country_code":       q.CountryCode,
		"hostname":           q.Hostname,
		"id":                 q.ID,
		"kind":               q.Kind,
		"src_country":        q.SrcCountry,
		"dst_country":        q.DstCountry,
		"src_ip":             q.SrcIP,
		"src_asn":            q.SrcASN,
		"vendor":             q.Vendor,
		"product":            q.Product,
		"version":            q.Version,
		"cpe":                q.CPE,
		"protocol":           q.Protocol,
		"transport":          q.Transport,
		"domain":             q.Domain,
		"classifications":    q.Classifications,
		"threat_actor":       q.ThreatActor,
		"mitre_id":           q.MitreID,
		"misp_id":            q.MispID,
		"ransomware":         q.Ransomware,
		"botnet":             q.Botnet,
		"jvndb":              q.JVNDB,
	} {
		if value != "" {
			p.Set(key, value)
		}
	}
	if q.Port > 0 {
		p.Set("port", strconv.Itoa(q.Port))
	}
	// contains_cve=false is a meaningful filter (hosts with no associated CVE), so
	// it is only omitted when the caller left it unset.
	if q.ContainsCVE != nil {
		p.Set("contains_cve", strconv.FormatBool(*q.ContainsCVE))
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

	return &IndexQueryResult{
		Data:       items,
		NextCursor: envelope.Meta.NextCursor,
		Total:      envelope.Meta.TotalDocuments,
	}, nil
}
