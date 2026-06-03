package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type IdentifyConfidence struct {
	Level  string `json:"level"`
	Source string `json:"source"`
}

type IdentifyIdentifier struct {
	Value      string             `json:"value"`
	Confidence IdentifyConfidence `json:"confidence"`
	Aliases    []string           `json:"aliases"`
}

type IdentifyIdentifiers struct {
	CPE  []IdentifyIdentifier `json:"cpe"`
	PURL []IdentifyIdentifier `json:"purl"`
}

type IdentifyResult struct {
	Identity struct {
		Part    string `json:"part"`
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
		Version string `json:"version"`
		Year    string `json:"year"`
	} `json:"identity"`
	Attributes struct {
		Update    string `json:"update"`
		Edition   string `json:"edition"`
		Language  string `json:"language"`
		SWEdition string `json:"sw_edition"`
		TargetSW  string `json:"target_sw"`
		TargetHW  string `json:"target_hw"`
		Other     string `json:"other"`
	} `json:"attributes"`
	Normalized struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"normalized"`
	Identifiers IdentifyIdentifiers `json:"identifiers"`
	Suggestions IdentifyIdentifiers `json:"suggestions"`
	Lifecycle   struct {
		CreatedAt string `json:"created_at"`
	} `json:"lifecycle"`
}

func (c *VulncheckClient) IdentifyComponent(ctx context.Context, vendor, product, version string) ([]IdentifyResult, error) {
	u, err := url.Parse(c.baseURL + "/v3/identify")
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}

	q := u.Query()
	q.Set("vendor", vendor)
	q.Set("product", product)
	if version != "" {
		q.Set("version", version)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req) //nolint:gosec // G704: baseURL is trusted config; index name is path-escaped
	if err != nil {
		return nil, fmt.Errorf("identify component request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identify component: HTTP %d: %s", resp.StatusCode, body)
	}

	var results []IdentifyResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if results == nil {
		return []IdentifyResult{}, nil
	}

	return results, nil
}
