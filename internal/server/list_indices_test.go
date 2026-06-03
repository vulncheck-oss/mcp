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
