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

func TestSearchIndex(t *testing.T) {
	const token = "test-token"

	type apiMeta struct {
		TotalDocuments int    `json:"total_documents"`
		NextCursor     string `json:"next_cursor,omitempty"`
	}
	type apiResponse struct {
		Meta apiMeta `json:"_meta"`
		Data any     `json:"data"`
	}

	tests := []struct {
		name       string
		query      SearchIndexQuery
		serverResp apiResponse
		statusCode int
		wantTotal  int
		wantLen    int
		wantCursor string
		wantErr    bool
		checkReq   func(t *testing.T, r *http.Request)
	}{
		{
			name:  "sets bearer token and returns results",
			query: SearchIndexQuery{Index: "vulncheck-nvd2", Limit: 5, StartCursor: true},
			serverResp: apiResponse{
				Meta: apiMeta{TotalDocuments: 42, NextCursor: "cursor-abc"},
				Data: []map[string]any{{"id": "CVE-2021-44228"}, {"id": "CVE-2022-0001"}},
			},
			statusCode: http.StatusOK,
			wantTotal:  42,
			wantLen:    2,
			wantCursor: "cursor-abc",
			checkReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
				assert.Equal(t, "vulncheck-mcp/test", r.Header.Get("User-Agent"))
				assert.Equal(t, "5", r.URL.Query().Get("limit"))
				assert.Equal(t, "/v3/index/vulncheck-nvd2", r.URL.Path)
				assert.Equal(t, "true", r.URL.Query().Get("start_cursor"))
			},
		},
		{
			name:  "passes cve and cursor query params",
			query: SearchIndexQuery{Index: "vulncheck-kev", CVE: "CVE-2021-44228", Cursor: "page2", Limit: 10},
			serverResp: apiResponse{
				Data: []map[string]any{},
			},
			statusCode: http.StatusOK,
			checkReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "CVE-2021-44228", r.URL.Query().Get("cve"))
				assert.Equal(t, "page2", r.URL.Query().Get("cursor"))
				assert.Empty(t, r.URL.Query().Get("start_cursor"))
			},
		},
		{
			name:  "passes date filter params",
			query: SearchIndexQuery{Index: "vulncheck-nvd2", Limit: 5, LastModStartDate: "2024-01-01", LastModEndDate: "2024-12-31", Sort: "date_added", Order: "desc"},
			serverResp: apiResponse{
				Data: []map[string]any{},
			},
			statusCode: http.StatusOK,
			checkReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "2024-01-01", r.URL.Query().Get("lastModStartDate"))
				assert.Equal(t, "2024-12-31", r.URL.Query().Get("lastModEndDate"))
				assert.Equal(t, "date_added", r.URL.Query().Get("sort"))
				assert.Equal(t, "desc", r.URL.Query().Get("order"))
			},
		},
		{
			name:  "passes alias and iava params",
			query: SearchIndexQuery{Index: "vulncheck-nvd2", Limit: 5, Alias: "GHSA-xxxx-xxxx-xxxx", IAVA: "2024-A-0001"},
			serverResp: apiResponse{
				Data: []map[string]any{},
			},
			statusCode: http.StatusOK,
			checkReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "GHSA-xxxx-xxxx-xxxx", r.URL.Query().Get("alias"))
				assert.Equal(t, "2024-A-0001", r.URL.Query().Get("iava"))
			},
		},
		{
			name:       "nil data returns empty slice",
			query:      SearchIndexQuery{Index: "empty-index", Limit: 1},
			serverResp: apiResponse{Meta: apiMeta{TotalDocuments: 0}, Data: nil},
			statusCode: http.StatusOK,
			wantLen:    0,
		},
		{
			name:       "non-200 response returns error",
			query:      SearchIndexQuery{Index: "vulncheck-nvd2", Limit: 1},
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

			result, err := vc.SearchIndex(t.Context(), tt.query)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTotal, result.Total)
			assert.Len(t, result.Data, tt.wantLen)
			assert.Equal(t, tt.wantCursor, result.NextCursor)
		})
	}
}

func TestSearchIndex_NetworkError(t *testing.T) {
	vc := &VulncheckClient{
		http:    &http.Client{},
		baseURL: "http://127.0.0.1:1",
		token:   "tok",
	}
	_, err := vc.SearchIndex(context.Background(), SearchIndexQuery{Index: "any", Limit: 1})
	require.Error(t, err)
}
