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

func TestMakeListAdvisoriesHandler(t *testing.T) {
	tests := []struct {
		name       string
		clientResp []client.Entry
		clientErr  error
		wantErr    bool
		wantTotal  int
		wantNames  []string
	}{
		{
			name: "returns advisory names",
			clientResp: []client.Entry{
				{Name: "rockwell"},
				{Name: "ubuntu"},
			},
			wantTotal: 2,
			wantNames: []string{"rockwell", "ubuntu"},
		},
		{
			name:       "empty result",
			clientResp: []client.Entry{},
			wantTotal:  0,
		},
		{
			name:      "client error propagates",
			clientErr: errors.New("unavailable"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockClient{
				listAdvisoriesFn: func(_ context.Context) ([]client.Entry, error) {
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeListAdvisoriesHandler(mock)
			result, _, err := handler(context.Background(), nil, struct{}{})

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
