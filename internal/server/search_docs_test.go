package server

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeSearchDocsHandler(t *testing.T) {
	t.Run("returns index content", func(t *testing.T) {
		const content = "# VulnCheck Docs\nhttps://docs.vulncheck.com/raw/getting-started.md\n"
		mock := &mockClient{
			searchDocsFn: func(_ context.Context) (string, error) {
				return content, nil
			},
		}
		handler := MakeSearchDocsHandler(mock)
		result, _, err := handler(context.Background(), nil, struct{}{})
		require.NoError(t, err)
		assert.Equal(t, content, result.Content[0].(*mcp.TextContent).Text)
	})

	t.Run("client error propagates", func(t *testing.T) {
		mock := &mockClient{
			searchDocsFn: func(_ context.Context) (string, error) {
				return "", errors.New("connection refused")
			},
		}
		handler := MakeSearchDocsHandler(mock)
		_, _, err := handler(context.Background(), nil, struct{}{})
		require.Error(t, err)
	})
}
