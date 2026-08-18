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
)

func TestMakeListIndicesHandler(t *testing.T) {
	tests := []struct {
		name       string
		args       listIndicesArgs
		clientResp []client.Entry
		clientErr  error
		wantErr    bool
		wantTotal  int
		wantNames  []string
	}{
		{
			name: "returns index names and descriptions",
			clientResp: []client.Entry{
				{Name: "vulncheck-nvd2", Description: "NVD CVE data"},
				{Name: "initial-access", Description: "Initial access exploits"},
			},
			wantTotal: 2,
			wantNames: []string{"vulncheck-nvd2", "initial-access"},
		},
		{
			name:       "empty result",
			clientResp: []client.Entry{},
			wantTotal:  0,
		},
		{
			name:      "client error propagates",
			clientErr: errors.New("auth failed"),
			wantErr:   true,
		},
		{
			name: "search filters by name",
			args: listIndicesArgs{Search: "nvd"},
			clientResp: []client.Entry{
				{Name: "vulncheck-nvd2", Description: "NVD CVE data"},
				{Name: "initial-access", Description: "Initial access exploits"},
			},
			wantTotal: 1,
			wantNames: []string{"vulncheck-nvd2"},
		},
		{
			name: "search filters by description case-insensitively",
			args: listIndicesArgs{Search: "INITIAL"},
			clientResp: []client.Entry{
				{Name: "vulncheck-nvd2", Description: "NVD CVE data"},
				{Name: "initial-access", Description: "Initial access exploits"},
			},
			wantTotal: 1,
			wantNames: []string{"initial-access"},
		},
		{
			name: "search with no match returns empty",
			args: listIndicesArgs{Search: "nonexistent"},
			clientResp: []client.Entry{
				{Name: "vulncheck-nvd2", Description: "NVD CVE data"},
			},
			wantTotal: 0,
		},
		{
			name: "empty search returns all entries",
			clientResp: []client.Entry{
				{Name: "vulncheck-nvd2", Description: "NVD CVE data"},
				{Name: "initial-access", Description: "Initial access exploits"},
			},
			wantTotal: 2,
			wantNames: []string{"vulncheck-nvd2", "initial-access"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockClient{
				listIndicesFn: func(_ context.Context) ([]client.Entry, error) {
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeListIndicesHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			text := result.Content[0].(*mcp.TextContent).Text
			var got listEntriesResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantTotal, got.Total)

			names := make([]string, len(got.Data))
			for i, e := range got.Data {
				names[i] = e.Name
			}
			for _, wantName := range tt.wantNames {
				assert.Contains(t, names, wantName)
			}
		})
	}
}

// The full catalogue is large and descriptions are the bulk of it, so a bare call
// returns names only. An agent is told to call this first, so its default cost
// matters more than its completeness.
func TestListIndices_OmitsDescriptionsByDefault(t *testing.T) {
	vc := &mockClient{
		listIndicesFn: func(_ context.Context) ([]client.Entry, error) {
			return []client.Entry{
				{Name: "exploits", Description: "a long description"},
				{Name: "vulncheck-nvd2", Description: "another long description"},
			}, nil
		},
	}

	res, _, err := MakeListIndicesHandler(vc)(context.Background(), nil, listIndicesArgs{})
	require.NoError(t, err)

	var got listEntriesResult
	require.NoError(t, json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &got))
	require.Len(t, got.Data, 2)
	for _, e := range got.Data {
		assert.NotEmpty(t, e.Name, "names are the point of the call")
		assert.Empty(t, e.Description)
	}
}

// A search narrows the set enough that descriptions are worth having, and asking for
// them separately would mean two calls to answer one question.
func TestListIndices_IncludesDescriptionsWhenSearching(t *testing.T) {
	vc := &mockClient{
		listIndicesFn: func(_ context.Context) ([]client.Entry, error) {
			return []client.Entry{
				{Name: "exploits", Description: "exploit intelligence"},
				{Name: "vulncheck-nvd2", Description: "vulnerability records"},
			}, nil
		},
	}

	res, _, err := MakeListIndicesHandler(vc)(context.Background(), nil, listIndicesArgs{Search: "exploit"})
	require.NoError(t, err)

	var got listEntriesResult
	require.NoError(t, json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &got))
	require.Len(t, got.Data, 1)
	assert.Equal(t, "exploit intelligence", got.Data[0].Description)
}

func TestListIndices_DescriptionOverrides(t *testing.T) {
	entries := []client.Entry{{Name: "exploits", Description: "exploit intelligence"}}
	vc := &mockClient{
		listIndicesFn: func(_ context.Context) ([]client.Entry, error) { return entries, nil },
	}
	on, off := true, false

	t.Run("forced on without a search", func(t *testing.T) {
		res, _, err := MakeListIndicesHandler(vc)(context.Background(), nil, listIndicesArgs{IncludeDescription: &on})
		require.NoError(t, err)
		var got listEntriesResult
		require.NoError(t, json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &got))
		assert.Equal(t, "exploit intelligence", got.Data[0].Description)
	})

	t.Run("forced off despite a search", func(t *testing.T) {
		res, _, err := MakeListIndicesHandler(vc)(context.Background(), nil,
			listIndicesArgs{Search: "exploit", IncludeDescription: &off})
		require.NoError(t, err)
		var got listEntriesResult
		require.NoError(t, json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &got))
		assert.Empty(t, got.Data[0].Description)
	})
}
