package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
	v2 "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func TestMakeSearchPURLsHandler(t *testing.T) {
	purl1 := "pkg:hex/coherence@0.1.2"
	purl2 := "pkg:conan/assimp@5.1.0"
	purlStrs := []string{purl1, purl2}

	tests := []struct {
		name       string
		args       searchPURLsArgs
		clientResp *client.SearchPURLsResult
		clientErr  error
		wantErr    bool
		wantTotal  int
		wantPURLs  []string
	}{
		{
			name: "returns findings for each purl",
			args: searchPURLsArgs{PURLs: purlStrs},
			clientResp: &client.SearchPURLsResult{
				Data: []v2.PurlBatchVulnFinding{
					{Purl: &purl1, Cves: []string{"CVE-2021-1234"}},
					{Purl: &purl2, Cves: []string{"CVE-2022-5678"}},
				},
				Total: 2,
			},
			wantTotal: 2,
			wantPURLs: purlStrs,
		},
		{
			name:       "empty result",
			args:       searchPURLsArgs{PURLs: purlStrs},
			clientResp: &client.SearchPURLsResult{Data: []v2.PurlBatchVulnFinding{}, Total: 0},
			wantTotal:  0,
		},
		{
			name:      "client error propagates",
			args:      searchPURLsArgs{PURLs: purlStrs},
			clientErr: errors.New("search failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPURLs []string

			mock := &mockClient{
				searchPURLsFn: func(_ context.Context, purls []string) (*client.SearchPURLsResult, error) {
					gotPURLs = purls
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeSearchPURLsHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.args.PURLs, gotPURLs)

			text := result.Content[0].(*mcp.TextContent).Text
			var got client.SearchPURLsResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantTotal, got.Total)

			if tt.wantPURLs != nil {
				require.Len(t, got.Data, len(tt.wantPURLs))
				for i, wantPURL := range tt.wantPURLs {
					assert.Equal(t, wantPURL, *got.Data[i].Purl)
				}
			}
		})
	}
}
