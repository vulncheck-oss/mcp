package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const docsHost = "https://docs.vulncheck.com"

func (c *VulncheckClient) SearchDocs(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docsHost+"/llms.txt", nil)
	if err != nil {
		return "", fmt.Errorf("searching docs: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("searching docs: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("searching docs: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("searching docs: unexpected status %d", resp.StatusCode)
	}

	return string(body), nil
}

func (c *VulncheckClient) GetDoc(ctx context.Context, docURL string) (string, error) {
	if !strings.HasPrefix(docURL, docsHost+"/raw/") || !strings.HasSuffix(docURL, ".md") {
		return "", fmt.Errorf("invalid doc URL: must be a %s/raw/ markdown URL", docsHost)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return "", fmt.Errorf("fetching doc: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching doc: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("fetching doc: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching doc: unexpected status %d", resp.StatusCode)
	}

	return string(body), nil
}
