package server

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeGetRulesHandler(t *testing.T) {
	const suricataRule = `alert tcp any any -> any any (msg:"test rule"; sid:1000001;)`
	const log4jRules = "alert tcp any any -> any any (msg:\"CVE-2021-44228 Log4Shell\"; sid:2000001;)\nalert udp any any -> any any (msg:\"CVE-2021-44228 JNDI\"; sid:2000002;)"
	const mixedRules = log4jRules + "\nalert tcp any any -> any any (msg:\"unrelated rule\"; sid:3000001;)"

	tests := []struct {
		name       string
		args       getRulesArgs
		clientResp string
		clientErr  error
		wantErr    bool
		wantType   string
		wantText   string
	}{
		{
			name:       "returns suricata rules",
			args:       getRulesArgs{Type: "suricata"},
			clientResp: suricataRule,
			wantType:   "suricata",
			wantText:   suricataRule,
		},
		{
			name:       "returns snort rules",
			args:       getRulesArgs{Type: "snort"},
			clientResp: suricataRule,
			wantType:   "snort",
			wantText:   suricataRule,
		},
		{
			name:      "client error propagates",
			args:      getRulesArgs{Type: "suricata"},
			clientErr: errors.New("not found"),
			wantErr:   true,
		},
		{
			name:       "cve filter returns matching lines",
			args:       getRulesArgs{Type: "suricata", CVE: "CVE-2021-44228"},
			clientResp: mixedRules,
			wantType:   "suricata",
			wantText:   log4jRules,
		},
		{
			name:       "cve filter is case-insensitive",
			args:       getRulesArgs{Type: "suricata", CVE: "cve-2021-44228"},
			clientResp: mixedRules,
			wantType:   "suricata",
			wantText:   log4jRules,
		},
		{
			name:       "cve filter with no match returns empty",
			args:       getRulesArgs{Type: "suricata", CVE: "CVE-9999-99999"},
			clientResp: mixedRules,
			wantType:   "suricata",
			wantText:   "",
		},
		{
			name:       "empty cve filter returns all rules",
			args:       getRulesArgs{Type: "suricata"},
			clientResp: mixedRules,
			wantType:   "suricata",
			wantText:   mixedRules,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotType string

			mock := &mockClient{
				getRulesFn: func(_ context.Context, ruleType string) (string, error) {
					gotType = ruleType
					return tt.clientResp, tt.clientErr
				},
			}

			handler := MakeGetRulesHandler(mock)
			result, _, err := handler(context.Background(), nil, tt.args)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantType, gotType)
			assert.Equal(t, tt.wantText, result.Content[0].(*mcp.TextContent).Text)
		})
	}
}
