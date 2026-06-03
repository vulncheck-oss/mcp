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
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

func TestMakeGetBackupHandler(t *testing.T) {
	backupURL := "https://example.com/backup.zip"
	tests := []struct {
		name       string
		index      string
		clientResp *client.GetBackupResult
		clientErr  error
		wantErr    bool
		wantIndex  string
		wantURL    string
	}{
		{
			name:  "returns backup links",
			index: "vulncheck-kev",
			clientResp: &client.GetBackupResult{
				Index: "vulncheck-kev",
				Data: []vulncheck.ParamsIndexBackup{
					{Url: &backupURL},
				},
			},
			wantIndex: "vulncheck-kev",
			wantURL:   "https://example.com/backup.zip",
		},
		{
			name:      "client error propagates",
			index:     "vulncheck-kev",
			clientErr: errors.New("not found"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotIndex string

			mock := &mockClient{
				getBackupFn: func(_ context.Context, index string) (*client.GetBackupResult, error) {
					gotIndex = index
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeGetBackupHandler(mock)
			result, _, err := handler(context.Background(), nil, getBackupArgs{Index: tt.index})

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.index, gotIndex)

			text := result.Content[0].(*mcp.TextContent).Text
			var got client.GetBackupResult
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantIndex, got.Index)
			require.Len(t, got.Data, 1)
			assert.Equal(t, tt.wantURL, *got.Data[0].Url)
		})
	}
}
