package server

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeListC2HostnamesHandler(t *testing.T) {
	const hostnames = "evil.example.com\nbad.example.net\nmalware.example.org"

	tests := []struct {
		name       string
		args       listC2HostnamesArgs
		clientResp string
		clientErr  error
		wantErr    bool
		wantText   string
	}{
		{
			name:       "returns hostname list",
			clientResp: hostnames,
			wantText:   hostnames,
		},
		{
			name:      "client error propagates",
			clientErr: errors.New("request failed"),
			wantErr:   true,
		},
		{
			name:       "search filters matching hostnames",
			args:       listC2HostnamesArgs{Search: "example.net"},
			clientResp: hostnames,
			wantText:   "bad.example.net",
		},
		{
			name:       "search is case-insensitive",
			args:       listC2HostnamesArgs{Search: "EVIL"},
			clientResp: hostnames,
			wantText:   "evil.example.com",
		},
		{
			name:       "search with no match returns empty",
			args:       listC2HostnamesArgs{Search: "notfound.example.com"},
			clientResp: hostnames,
			wantText:   "",
		},
		{
			name:       "empty search returns all hostnames",
			clientResp: hostnames,
			wantText:   hostnames,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockClient{
				listC2HostnamesFn: func(_ context.Context) (string, error) {
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeListC2HostnamesHandler(mock)
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
