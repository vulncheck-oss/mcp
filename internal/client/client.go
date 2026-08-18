package client

import (
	"context"
	"net/http"
	"time"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

// Client defines all VulnCheck API operations needed by MCP tools.
type Client interface {
	// V3 Endpoints
	ListC2Tags(ctx context.Context) (string, error)
	ListIndices(ctx context.Context) ([]Entry, error)
	ListBackups(ctx context.Context) ([]Entry, error)
	ListC2Hostnames(ctx context.Context) (string, error)
	SearchIndex(ctx context.Context, q SearchIndexQuery) (*IndexQueryResult, error)
	DescribeIndex(ctx context.Context, index string) (*IndexDescription, error)
	GetBackup(ctx context.Context, index string) (*GetBackupResult, error)
	GetCPECVEs(ctx context.Context, cpe string, vulnerableOnly bool) (*CPECVEsResult, error)
	SearchCPE(ctx context.Context, q SearchCPEQuery) (*SearchCPEResult, error)
	SearchPURLs(ctx context.Context, purls []string) (*SearchPURLsResult, error)
	IdentifyComponent(ctx context.Context, vendor, product, version string) ([]IdentifyResult, error)
	GetRules(ctx context.Context, ruleType string) (string, error)
	SearchCVE(ctx context.Context, q SearchCVEQuery) (*SearchCVEResult, error)
	SearchDocs(ctx context.Context) (string, error)
	GetDoc(ctx context.Context, docURL string) (string, error)
	// V4 Endpoints
	ListAdvisories(ctx context.Context) ([]Entry, error)
	SearchAdvisory(ctx context.Context, q SearchAdvisoryQuery) (*SearchAdvisoryResult, error)
	ListAdvisoryBackups(ctx context.Context) ([]vulncheck.BackupFeedItem, error)
	GetAdvisoryBackup(ctx context.Context, name string) (*vulncheck.BackupBackupResponse, error)
}

// VulncheckClient is the concrete client backed by the VulnCheck public API.
type VulncheckClient struct {
	sdk       *vulncheck.APIClient
	http      *http.Client
	baseURL   string
	token     string
	userAgent string
}

// New returns a VulncheckClient ready to use against the VulnCheck public API.
func New(token, version string) *VulncheckClient {
	ua := "vulncheck-mcp/" + version
	cfg := vulncheck.NewConfiguration()
	cfg.UserAgent = ua
	return &VulncheckClient{
		sdk:       vulncheck.NewAPIClient(cfg),
		http:      &http.Client{Timeout: 30 * time.Second},
		baseURL:   "https://api.vulncheck.com",
		token:     token,
		userAgent: ua,
	}
}

func (c *VulncheckClient) authContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, vulncheck.ContextAPIKeys, map[string]vulncheck.APIKey{
		"Bearer": {Key: c.token},
	})
}
