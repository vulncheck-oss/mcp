package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newSDKTestClient(fn roundTripFunc) *VulncheckClient {
	cfg := vulncheck.NewConfiguration()
	cfg.HTTPClient = &http.Client{Transport: fn}
	return &VulncheckClient{
		sdk:       vulncheck.NewAPIClient(cfg),
		http:      &http.Client{Timeout: 5 * time.Second},
		baseURL:   "https://api.vulncheck.com",
		token:     "test-token",
		userAgent: "vulncheck-mcp/test",
	}
}

func jsonResp(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

// newAPITestClient builds a client for the endpoints that issue their own HTTP
// requests rather than going through the generated SDK, so the fake transport has
// to sit on c.http instead of on the SDK configuration.
func newAPITestClient(fn roundTripFunc) *VulncheckClient {
	return &VulncheckClient{
		http:      &http.Client{Transport: fn},
		baseURL:   "https://api.vulncheck.com",
		token:     "test-token",
		userAgent: "vulncheck-mcp/test",
	}
}

func newDocsTestClient(fn roundTripFunc) *VulncheckClient {
	return &VulncheckClient{
		http:      &http.Client{Transport: fn},
		userAgent: "vulncheck-mcp/test",
	}
}

func errResp(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"message":"error"}`)),
	}
}
