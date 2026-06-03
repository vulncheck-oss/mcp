package server

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeListC2TagsHandler(t *testing.T) {
	const ips = "1.2.3.4\n5.6.7.8\n9.10.11.12"

	tests := []struct {
		name       string
		args       listC2TagsArgs
		clientResp string
		clientErr  error
		wantErr    bool
		wantText   string
	}{
		{
			name:       "returns IP list",
			clientResp: ips,
			wantText:   ips,
		},
		{
			name:      "client error propagates",
			clientErr: errors.New("request failed"),
			wantErr:   true,
		},
		{
			name:       "search filters matching IPs",
			args:       listC2TagsArgs{Search: "1.2.3"},
			clientResp: ips,
			wantText:   "1.2.3.4",
		},
		{
			name:       "search with no match returns empty",
			args:       listC2TagsArgs{Search: "99.99.99.99"},
			clientResp: ips,
			wantText:   "",
		},
		{
			name:       "empty search returns all IPs",
			clientResp: ips,
			wantText:   ips,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockClient{
				listC2TagsFn: func(_ context.Context) (string, error) {
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeListC2TagsHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantText, result.Content[0].(*mcp.TextContent).Text)
		})
	}
}
