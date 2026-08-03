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

func TestSearchPURLsVersionlessNote(t *testing.T) {
	mock := &mockClient{
		searchPURLsFn: func(_ context.Context, _ []string) (*client.SearchPURLsResult, error) {
			return &client.SearchPURLsResult{Data: []v2.PurlBatchVulnFinding{}, Total: 0}, nil
		},
	}
	handler := MakeSearchPURLsHandler(mock)

	decode := func(t *testing.T, result *mcp.CallToolResult) searchPURLsResponse {
		t.Helper()
		var got searchPURLsResponse
		got.SearchPURLsResult = &client.SearchPURLsResult{}
		text := result.Content[0].(*mcp.TextContent).Text
		require.NoError(t, json.Unmarshal([]byte(text), &got))
		return got
	}

	t.Run("versionless purls are named in a note", func(t *testing.T) {
		// The versionless PURL must differ from the example the note itself cites,
		// or the assertion below passes on that example alone.
		result, _, err := handler(context.Background(), nil, searchPURLsArgs{
			PURLs: []string{"pkg:golang/github.com/gin-gonic/gin", "pkg:npm/@anthropic-ai/claude-code@1.0.0"},
		})
		require.NoError(t, err)

		got := decode(t, result)
		assert.Contains(t, got.Note, "pkg:golang/github.com/gin-gonic/gin")
		assert.NotContains(t, got.Note, "claude-code@1.0.0")
	})

	t.Run("fully versioned purls produce no note", func(t *testing.T) {
		result, _, err := handler(context.Background(), nil, searchPURLsArgs{
			PURLs: []string{"pkg:npm/@anthropic-ai/claude-code@1.0.0", "pkg:hex/coherence@0.1.2"},
		})
		require.NoError(t, err)
		assert.Empty(t, decode(t, result).Note)
	})
}

func TestPurlLacksVersion(t *testing.T) {
	assert.True(t, purlLacksVersion("pkg:npm/@openai/codex"), "namespace @ must not count as a version")
	assert.True(t, purlLacksVersion("pkg:npm/%40openai/codex"))
	assert.True(t, purlLacksVersion("pkg:golang/github.com/gin-gonic/gin"))
	assert.True(t, purlLacksVersion("pkg:npm/lodash?arch=x86"), "qualifiers are not a version")

	assert.False(t, purlLacksVersion("pkg:npm/@openai/codex@0.30.0"))
	assert.False(t, purlLacksVersion("pkg:npm/lodash@4.17.21"))
	assert.False(t, purlLacksVersion("pkg:hex/coherence@0.1.2"))
	assert.False(t, purlLacksVersion("pkg:npm/lodash@4.17.21?arch=x86#sub/path"))
}
