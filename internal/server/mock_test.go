package server

import (
	"context"

	"github.com/vulncheck-oss/mcp/internal/client"
	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

type mockClient struct {
	listIndicesFn         func(ctx context.Context) ([]client.Entry, error)
	listBackupsFn         func(ctx context.Context) ([]client.Entry, error)
	getBackupFn           func(ctx context.Context, index string) (*client.GetBackupResult, error)
	searchIndexFn         func(ctx context.Context, q client.SearchIndexQuery) (*client.IndexQueryResult, error)
	describeIndexFn       func(ctx context.Context, index string) (*client.IndexDescription, error)
	getCPECVEsFn          func(ctx context.Context, cpe string, vulnerableOnly bool) (*client.CPECVEsResult, error)
	searchCPEFn           func(ctx context.Context, q client.SearchCPEQuery) (*client.SearchCPEResult, error)
	searchPURLsFn         func(ctx context.Context, purls []string) (*client.SearchPURLsResult, error)
	identifyComponentFn   func(ctx context.Context, vendor, product, version string) ([]client.IdentifyResult, error)
	getRulesFn            func(ctx context.Context, ruleType string) (string, error)
	listC2TagsFn          func(ctx context.Context) (string, error)
	listC2HostnamesFn     func(ctx context.Context) (string, error)
	listAdvisoriesFn      func(ctx context.Context) ([]client.Entry, error)
	searchAdvisoryFn      func(ctx context.Context, q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error)
	listAdvisoryBackupsFn func(ctx context.Context) ([]vulncheck.BackupFeedItem, error)
	getAdvisoryBackupFn   func(ctx context.Context, name string) (*vulncheck.BackupBackupResponse, error)
	searchCVEFn           func(ctx context.Context, q client.SearchCVEQuery) (*client.SearchCVEResult, error)
	searchDocsFn          func(ctx context.Context) (string, error)
	getDocFn              func(ctx context.Context, url string) (string, error)
}

func (m *mockClient) ListIndices(ctx context.Context) ([]client.Entry, error) {
	return m.listIndicesFn(ctx)
}

func (m *mockClient) ListBackups(ctx context.Context) ([]client.Entry, error) {
	return m.listBackupsFn(ctx)
}

func (m *mockClient) GetBackup(ctx context.Context, index string) (*client.GetBackupResult, error) {
	return m.getBackupFn(ctx, index)
}

func (m *mockClient) SearchIndex(ctx context.Context, q client.SearchIndexQuery) (*client.IndexQueryResult, error) {
	return m.searchIndexFn(ctx, q)
}

func (m *mockClient) DescribeIndex(ctx context.Context, index string) (*client.IndexDescription, error) {
	return m.describeIndexFn(ctx, index)
}

func (m *mockClient) GetCPECVEs(ctx context.Context, cpe string, vulnerableOnly bool) (*client.CPECVEsResult, error) {
	return m.getCPECVEsFn(ctx, cpe, vulnerableOnly)
}

func (m *mockClient) SearchCPE(ctx context.Context, q client.SearchCPEQuery) (*client.SearchCPEResult, error) {
	return m.searchCPEFn(ctx, q)
}

func (m *mockClient) SearchPURLs(ctx context.Context, purls []string) (*client.SearchPURLsResult, error) {
	return m.searchPURLsFn(ctx, purls)
}

func (m *mockClient) IdentifyComponent(ctx context.Context, vendor, product, version string) ([]client.IdentifyResult, error) {
	return m.identifyComponentFn(ctx, vendor, product, version)
}

func (m *mockClient) GetRules(ctx context.Context, ruleType string) (string, error) {
	return m.getRulesFn(ctx, ruleType)
}

func (m *mockClient) ListC2Tags(ctx context.Context) (string, error) {
	return m.listC2TagsFn(ctx)
}

func (m *mockClient) ListC2Hostnames(ctx context.Context) (string, error) {
	return m.listC2HostnamesFn(ctx)
}

func (m *mockClient) ListAdvisories(ctx context.Context) ([]client.Entry, error) {
	return m.listAdvisoriesFn(ctx)
}

func (m *mockClient) SearchAdvisory(ctx context.Context, q client.SearchAdvisoryQuery) (*client.SearchAdvisoryResult, error) {
	return m.searchAdvisoryFn(ctx, q)
}

func (m *mockClient) ListAdvisoryBackups(ctx context.Context) ([]vulncheck.BackupFeedItem, error) {
	return m.listAdvisoryBackupsFn(ctx)
}

func (m *mockClient) GetAdvisoryBackup(ctx context.Context, name string) (*vulncheck.BackupBackupResponse, error) {
	return m.getAdvisoryBackupFn(ctx, name)
}

func (m *mockClient) SearchCVE(ctx context.Context, q client.SearchCVEQuery) (*client.SearchCVEResult, error) {
	return m.searchCVEFn(ctx, q)
}

func (m *mockClient) SearchDocs(ctx context.Context) (string, error) {
	return m.searchDocsFn(ctx)
}

func (m *mockClient) GetDoc(ctx context.Context, url string) (string, error) {
	return m.getDocFn(ctx, url)
}
