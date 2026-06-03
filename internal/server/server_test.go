package server

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer_ToolsRegistered(t *testing.T) {
	srv := New(&mockClient{}, "test", nil)
	require.NotNil(t, srv)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.Run(ctx, serverTransport) //nolint:errcheck

	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := c.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })

	resp, err := session.ListTools(ctx, nil)
	require.NoError(t, err)

	names := make([]string, len(resp.Tools))
	for i, tool := range resp.Tools {
		names[i] = tool.Name
	}

	assert.Contains(t, names, "list_indices")
	assert.Contains(t, names, "search_index")
	assert.Contains(t, names, "get_cpe_cves")
	assert.Contains(t, names, "search_cpe")
}
