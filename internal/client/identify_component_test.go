package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifyComponent(t *testing.T) {
	const token = "test-token"

	tests := []struct {
		name       string
		vendor     string
		product    string
		version    string
		serverResp []IdentifyResult
		statusCode int
		wantLen    int
		wantErr    bool
		checkReq   func(t *testing.T, r *http.Request)
	}{
		{
			name:    "returns results with all query params",
			vendor:  "microsoft corporation",
			product: "office 2016",
			version: "16.0.1",
			serverResp: []IdentifyResult{
				{Identity: struct {
					Part    string `json:"part"`
					Vendor  string `json:"vendor"`
					Product string `json:"product"`
					Version string `json:"version"`
					Year    string `json:"year"`
				}{Vendor: "microsoft corporation", Product: "office 2016"}},
			},
			statusCode: http.StatusOK,
			wantLen:    1,
			checkReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
				assert.Equal(t, "vulncheck-mcp/test", r.Header.Get("User-Agent"))
				assert.Equal(t, "/v3/identify", r.URL.Path)
				assert.Equal(t, "microsoft corporation", r.URL.Query().Get("vendor"))
				assert.Equal(t, "office 2016", r.URL.Query().Get("product"))
				assert.Equal(t, "16.0.1", r.URL.Query().Get("version"))
			},
		},
		{
			name:       "omits version param when empty",
			vendor:     "linux",
			product:    "kernel",
			serverResp: []IdentifyResult{},
			statusCode: http.StatusOK,
			checkReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Empty(t, r.URL.Query().Get("version"))
			},
		},
		{
			name:       "nil response normalized to empty slice",
			vendor:     "x",
			product:    "y",
			serverResp: nil,
			statusCode: http.StatusOK,
			wantLen:    0,
		},
		{
			name:       "non-200 status returns error",
			vendor:     "x",
			product:    "y",
			statusCode: http.StatusUnauthorized,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.checkReq != nil {
					tt.checkReq(t, r)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					_ = json.NewEncoder(w).Encode(tt.serverResp)
				} else {
					_, _ = fmt.Fprint(w, "unauthorized")
				}
			}))
			defer srv.Close()

			vc := &VulncheckClient{
				http:      srv.Client(),
				baseURL:   srv.URL,
				token:     token,
				userAgent: "vulncheck-mcp/test",
			}

			result, err := vc.IdentifyComponent(t.Context(), tt.vendor, tt.product, tt.version)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, result, tt.wantLen)
		})
	}
}

func TestIdentifyComponent_NetworkError(t *testing.T) {
	vc := &VulncheckClient{
		http:      &http.Client{},
		baseURL:   "http://127.0.0.1:1",
		token:     "tok",
		userAgent: "vulncheck-mcp/test",
	}
	_, err := vc.IdentifyComponent(context.Background(), "vendor", "product", "")
	require.Error(t, err)
}
