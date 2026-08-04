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

type SearchAdvisoryQuery struct {
	Name          string
	CveID         string
	Vendor        string
	Product       string
	Platform      string
	Version       string
	CPE           string
	PackageName   string
	PURL          string
	UpdatedAfter  string
	UpdatedBefore string
	Limit         int32
	StartCursor   bool
	Cursor        string
}

// SearchAdvisoryResult holds advisory records as raw JSON rather than generated
// structs.
//
// The MCP server passes these records straight to the model and only ever reads
// two paths itself (cveMetadata.cveId, and affected[].product/packageName), so
// typing the payload buys nothing and couples the server to the API's OpenAPI
// codegen. That coupling is not hypothetical: the generated types cannot decode
// roughly 80% of /v4/advisory responses, because containers.*.source and
// containers.*.metrics[].other.content are served as JSON strings wrapping JSON
// objects. Raw passthrough is immune to that whole class of mismatch, and stays
// correct once the upstream double-encoding is fixed.
type SearchAdvisoryResult struct {
	Data       []json.RawMessage `json:"data"`
	Total      int32             `json:"total"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// advisoryEnvelope is the wire shape of /v4/advisory.
type advisoryEnvelope struct {
	Data []json.RawMessage `json:"data"`
	Meta *struct {
		Total      int32  `json:"total"`
		NextCursor string `json:"next_cursor"`
	} `json:"_meta"`
}

// SearchAdvisory queries /v4/advisory directly rather than through the generated
// SDK client, so that a response the SDK's types reject still reaches the caller.
// This follows the hand-rolled pattern already used by SearchIndex and
// IdentifyComponent.
func (c *VulncheckClient) SearchAdvisory(ctx context.Context, q SearchAdvisoryQuery) (*SearchAdvisoryResult, error) {
	u, err := url.Parse(c.baseURL + "/v4/advisory")
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}

	p := u.Query()
	for key, value := range map[string]string{
		"name":          q.Name,
		"cve_id":        q.CveID,
		"vendor":        q.Vendor,
		"product":       q.Product,
		"platform":      q.Platform,
		"version":       q.Version,
		"cpe":           q.CPE,
		"package_name":  q.PackageName,
		"purl":          q.PURL,
		"updatedAfter":  q.UpdatedAfter,
		"updatedBefore": q.UpdatedBefore,
		"cursor":        q.Cursor,
	} {
		if value != "" {
			p.Set(key, value)
		}
	}
	if q.Cursor == "" && q.StartCursor {
		p.Set("start_cursor", "true")
	}
	if q.Limit > 0 {
		p.Set("limit", strconv.FormatInt(int64(q.Limit), 10))
	}
	u.RawQuery = p.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req) //nolint:gosec // G704: baseURL is trusted config
	if err != nil {
		return nil, fmt.Errorf("searching advisories: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("searching advisories: HTTP %d: %s", resp.StatusCode, body)
	}

	var envelope advisoryEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	data := envelope.Data
	if data == nil {
		data = []json.RawMessage{}
	}

	result := &SearchAdvisoryResult{Data: data}
	if envelope.Meta != nil {
		result.Total = envelope.Meta.Total
		result.NextCursor = envelope.Meta.NextCursor
	}

	return result, nil
}
