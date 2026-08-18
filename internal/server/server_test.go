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

// TestServerInstructions_RoutesExposureQuestionsAwayFromSearchCVE guards the
// routing contract, not the prose. search_cve is served by /v3/search/cve, whose
// index set does not include target-intel, ipintel-* or vulncheck-canaries*, so
// the instructions must not claim it answers exposure or observed-attack
// questions, and must name the indices that do.
func TestServerInstructions_RoutesExposureQuestionsAwayFromSearchCVE(t *testing.T) {
	t.Run("names the indices search_cve cannot reach", func(t *testing.T) {
		for _, index := range []string{"target-intel", "ipintel-3d", "vulncheck-canaries"} {
			assert.Contains(t, serverInstructions, index,
				"instructions must name %q, the only source for exposure or observed-attack questions", index)
		}
	})

	t.Run("does not claim search_cve is sufficient for every category", func(t *testing.T) {
		// The prior wording promised a question mentioning threat intelligence was
		// "fully answered by search_cve alone", which is false for the three indices
		// above and left them unreachable in practice.
		assert.NotContains(t, serverInstructions, "fully answered by search_cve alone")
		assert.Contains(t, serverInstructions, "search_cve does not cover these")
	})

	t.Run("keeps the fan-out and pagination guardrails from #39", func(t *testing.T) {
		assert.Contains(t, serverInstructions, "Do not paginate autonomously")
		assert.Contains(t, serverInstructions, "Do not call search_index to cross-check or enrich")
	})

	t.Run("warns that the default limit is not a population answer", func(t *testing.T) {
		// search_index defaults limit to 1, which is misleading rather than merely
		// small when the question is "which hosts are exposed".
		assert.Contains(t, serverInstructions, "Pass an explicit limit")
		assert.Contains(t, serverInstructions, "population size from the response total")
	})
}
