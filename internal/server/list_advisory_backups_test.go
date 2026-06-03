package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func TestMakeListAdvisoryBackupsHandler(t *testing.T) {
	name := "ghsa"
	available := true

	tests := []struct {
		name       string
		clientResp []vulncheck.BackupFeedItem
		clientErr  error
		wantErr    bool
		wantTotal  int
		wantNames  []string
	}{
		{
			name: "returns feeds with availability",
			clientResp: []vulncheck.BackupFeedItem{
				{Name: &name, Available: &available},
			},
			wantTotal: 1,
			wantNames: []string{"ghsa"},
		},
		{
			name:       "empty result",
			clientResp: []vulncheck.BackupFeedItem{},
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
				listAdvisoryBackupsFn: func(_ context.Context) ([]vulncheck.BackupFeedItem, error) {
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeListAdvisoryBackupsHandler(mock)
			result, _, err := handler(context.Background(), nil, struct{}{})

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			text := result.Content[0].(*mcp.TextContent).Text
			var got listAdvisoryBackupsResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantTotal, got.Total)

			names := make([]string, 0, len(got.Data))
			for _, e := range got.Data {
				if e.Name != nil {
					names = append(names, *e.Name)
				}
			}
			for _, wantName := range tt.wantNames {
				assert.Contains(t, names, wantName)
			}
		})
	}
}
