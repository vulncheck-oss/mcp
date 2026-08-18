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
	t.Run("routes to the tools that own the data search_cve cannot reach", func(t *testing.T) {
		for _, tool := range []string{"search_target_intel", "search_ip_intel", "search_canaries", "search_curated_exploits"} {
			assert.Contains(t, serverInstructions, tool,
				"instructions must name %q, the only route to exposure or observed-attack data", tool)
		}
	})

	t.Run("does not advertise the raw indices behind those tools", func(t *testing.T) {
		// The product tools expose filters search_index cannot, so naming the raw
		// index would point callers at the worse path.
		for _, index := range []string{"target-intel", "ipintel-3d", "vulncheck-canaries-3d"} {
			assert.NotContains(t, serverInstructions, index,
				"instructions should route via the product tool, not the raw index %q", index)
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

	// search_cve reports maturity and KEV status for a named CVE but cannot select by
	// them. Describing that boundary as a topic rather than a direction sent every
	// "which CVEs are weaponized" question to the one tool that cannot answer it.
	t.Run("separates reporting a CVE's properties from selecting CVEs by them", func(t *testing.T) {
		assert.Contains(t, serverInstructions, "cannot select by them")
		assert.Contains(t, serverInstructions, "weaponized exploit code")
	})

	t.Run("says a product result is a sample of a population", func(t *testing.T) {
		// These indices are far larger than any single response, so a result is
		// never the complete set. The advice to pass an explicit limit is gone because
		// the product tools default to sensible page sizes instead of search_index's 1.
		assert.Contains(t, serverInstructions, "return a sample")
		assert.Contains(t, serverInstructions, "report total rather than counting the rows returned")
	})
}
