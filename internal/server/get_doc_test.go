package server

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeGetDocHandler(t *testing.T) {
	const docURL = "https://docs.vulncheck.com/raw/getting-started/api-tokens.md"
	const content = "# API Tokens\nCreate tokens at console.vulncheck.com\n"

	t.Run("returns markdown content", func(t *testing.T) {
		var gotURL string
		mock := &mockClient{
			getDocFn: func(_ context.Context, url string) (string, error) {
				gotURL = url
				return content, nil
			},
		}
		handler := MakeGetDocHandler(mock)
		result, _, err := handler(context.Background(), nil, getDocArgs{URL: docURL})
		require.NoError(t, err)
		assert.Equal(t, docURL, gotURL)
		assert.Equal(t, content, result.Content[0].(*mcp.TextContent).Text)
	})

	t.Run("client error propagates", func(t *testing.T) {
		mock := &mockClient{
			getDocFn: func(_ context.Context, _ string) (string, error) {
				return "", errors.New("not found")
			},
		}
		handler := MakeGetDocHandler(mock)
		_, _, err := handler(context.Background(), nil, getDocArgs{URL: docURL})
		require.Error(t, err)
	})
}
