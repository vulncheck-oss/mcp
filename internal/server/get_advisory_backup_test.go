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

func TestMakeGetAdvisoryBackupHandler(t *testing.T) {
	feed := "ghsa"
	available := true
	urlMrap := "https://s3.example.com/ghsa.zip"

	tests := []struct {
		name       string
		args       getAdvisoryBackupArgs
		clientResp *vulncheck.BackupBackupResponse
		clientErr  error
		wantErr    bool
		wantFeed   string
	}{
		{
			name: "returns backup URLs for feed",
			args: getAdvisoryBackupArgs{Name: feed},
			clientResp: &vulncheck.BackupBackupResponse{
				Feed:      &feed,
				Available: &available,
				UrlMrap:   &urlMrap,
			},
			wantFeed: feed,
		},
		{
			name:      "client error propagates",
			args:      getAdvisoryBackupArgs{Name: "unknown"},
			clientErr: errors.New("feed not found"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotName string

			mock := &mockClient{
				getAdvisoryBackupFn: func(_ context.Context, name string) (*vulncheck.BackupBackupResponse, error) {
					gotName = name
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeGetAdvisoryBackupHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.args.Name, gotName)

			text := result.Content[0].(*mcp.TextContent).Text
			var got vulncheck.BackupBackupResponse
			require.NoError(t, json.Unmarshal([]byte(text), &got))
			assert.Equal(t, tt.wantFeed, *got.Feed)
		})
	}
}
