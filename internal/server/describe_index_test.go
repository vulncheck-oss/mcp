package server

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulncheck-oss/mcp/internal/client"
)

func describeMock(desc *client.IndexDescription, err error) *mockClient {
	return &mockClient{
		describeIndexFn: func(_ context.Context, index string) (*client.IndexDescription, error) {
			if err != nil {
				return nil, err
			}
			if desc != nil {
				return desc, nil
			}
			return &client.IndexDescription{Name: index}, nil
		},
	}
}

func decodeDescribe(t *testing.T, res *mcp.CallToolResult) describeIndexResult {
	t.Helper()
	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	var got describeIndexResult
	require.NoError(t, json.Unmarshal([]byte(text.Text), &got))
	return got
}

// Every index with a dedicated tool must name a tool that is actually registered,
// or describe_index would send callers to something that does not exist.
func TestDedicatedTools_NameRegisteredTools(t *testing.T) {
	srv := New(&mockClient{}, "test", nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx, serverTransport) }()

	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	listed, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	names := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}

	for index, tool := range dedicatedTools {
		assert.True(t, slices.Contains(names, tool),
			"index %q points at tool %q, which is not registered", index, tool)
	}
	assert.True(t, slices.Contains(names, "search_index"), "the generic fallback must exist")
}

func TestDescribeIndex_ReportsFiltersAndSize(t *testing.T) {
	vc := describeMock(&client.IndexDescription{
		Name: "vulncheck-nvd2",
		Filters: []client.IndexFilter{
			{Name: "cve", Accepts: "CVE-YYYY-N{4-7}"},
			{Name: "alias"},
			{Name: "threat_actor"},
			{Name: "kind"},
		},
		TotalDocuments: 384273,
		DefaultSort:    "lastModified",
	}, nil)

	res, _, err := MakeDescribeIndexHandler(vc)(context.Background(), nil, describeIndexArgs{Index: "vulncheck-nvd2"})
	require.NoError(t, err)

	got := decodeDescribe(t, res)
	assert.Equal(t, "vulncheck-nvd2", got.Name)
	assert.Equal(t, 384273, got.TotalDocuments)
	assert.Equal(t, "lastModified", got.DefaultSort)
	assert.Equal(t, []client.IndexFilter{
		{Name: "cve", Accepts: "CVE-YYYY-N{4-7}"},
		{Name: "alias"},
		{Name: "threat_actor"},
		{Name: "kind"},
	}, got.Filters, "the accepted values come through, not just the names")
}

// An index without a dedicated tool is served by search_index, which cannot send
// every filter the index advertises. Reporting the intersection is what stops a
// caller assuming an advertised filter is reachable.
func TestDescribeIndex_ReportsWhichFiltersTheGenericToolCanSend(t *testing.T) {
	vc := describeMock(&client.IndexDescription{
		Name: "vulncheck-nvd2",
		Filters: []client.IndexFilter{
			{Name: "cve"}, {Name: "threat_actor"}, {Name: "kind"}, {Name: "matches"},
		},
	}, nil)

	res, _, err := MakeDescribeIndexHandler(vc)(context.Background(), nil, describeIndexArgs{Index: "vulncheck-nvd2"})
	require.NoError(t, err)

	got := decodeDescribe(t, res)
	assert.Equal(t, "search_index", got.Tool)
	assert.Equal(t, []string{"cve", "threat_actor"}, got.SupportedByTool,
		"kind and matches are advertised but search_index has no argument for them")
	assert.Contains(t, strings.Join(got.Notes, " "), "search_index")
}

func TestDescribeIndex_PointsAtTheDedicatedTool(t *testing.T) {
	for index, want := range map[string]string{
		"target-intel":          "search_target_intel",
		"ipintel-30d":           "search_ip_intel",
		"vulncheck-canaries":    "search_canaries",
		"vulncheck-canaries-3d": "search_canaries",
	} {
		t.Run(index, func(t *testing.T) {
			vc := describeMock(&client.IndexDescription{
				Name:    index,
				Filters: []client.IndexFilter{{Name: "cve"}, {Name: "asn", Accepts: "AS[0-9]+"}},
			}, nil)
			res, _, err := MakeDescribeIndexHandler(vc)(context.Background(), nil, describeIndexArgs{Index: index})
			require.NoError(t, err)

			got := decodeDescribe(t, res)
			assert.Equal(t, want, got.Tool)
			assert.Contains(t, strings.Join(got.Notes, " "), "dedicated tool")
			assert.Empty(t, got.SupportedByTool,
				"a dedicated tool exposes the index's filters, so the subset is not the interesting fact")
		})
	}
}

func TestDescribeIndex_PropagatesErrors(t *testing.T) {
	_, _, err := MakeDescribeIndexHandler(describeMock(nil, errors.New("nope")))(
		context.Background(), nil, describeIndexArgs{Index: "nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "describing index")
}

// The published values are the point of this tool as much as the names are. Guessing a
// vocabulary, or taking one from documentation, has produced filters that were accepted
// and then silently not applied.
func TestDescribeIndex_ReportsTheAcceptedValues(t *testing.T) {
	vc := describeMock(&client.IndexDescription{
		Name: "exploits",
		Filters: []client.IndexFilter{
			{Name: "max_exploit_maturity", Accepts: "poc|weaponized"},
			{Name: "in_kev", Accepts: "true|false"},
			{Name: "cve", Accepts: "^CVE-\\d{4}-\\d{4,7}$"},
			{Name: "vendor"},
		},
	}, nil)

	res, _, err := MakeDescribeIndexHandler(vc)(context.Background(), nil, describeIndexArgs{Index: "exploits"})
	require.NoError(t, err)

	got := decodeDescribe(t, res)
	byName := map[string]string{}
	for _, f := range got.Filters {
		byName[f.Name] = f.Accepts
	}
	assert.Equal(t, "poc|weaponized", byName["max_exploit_maturity"],
		"a closed vocabulary is reported so a caller need not guess it")
	assert.Equal(t, "true|false", byName["in_kev"])
	assert.Equal(t, "^CVE-\\d{4}-\\d{4,7}$", byName["cve"],
		"a pattern is reported verbatim for free-form parameters")
	assert.Empty(t, byName["vendor"], "a parameter with no published values reports none")
}
