package client

import (
	"context"
	"errors"
	"fmt"

	vulncheck "github.com/vulncheck-oss/sdk-go-v2/v2"
)

// NVDPage is the paging shared by the NVD API 2.0 compatible endpoints.
//
// Four of the five page by cursor, which the API only issues to a caller who opts in by
// sending `cursor`, empty on the first page. /source/2.0 has no cursor and pages by
// StartIndex alone.
type NVDPage struct {
	Limit       int32
	StartCursor bool
	Cursor      string
	StartIndex  int32
}

// NVDResult carries one page of NVD records.
//
// Data holds the records themselves rather than NVD's per-row wrappers ({"cve": ...},
// {"change": ...}): each wrapper has a single key, and unwrapping puts the identifiers
// (id, cveId, matchCriteriaId, cpeName) where the response cap looks for them to name
// records it withholds.
type NVDResult[T any] struct {
	Data       []T
	Total      int
	NextCursor string
}

type NVDCVEsQuery struct {
	CVEID              string
	CPEName            string
	IsVulnerable       bool
	VirtualMatchString string
	VersionStart       string
	VersionStartType   string
	VersionEnd         string
	VersionEndType     string
	CVETag             string
	HasKEV             bool
	NoRejected         bool
	PubStartDate       string
	PubEndDate         string
	LastModStartDate   string
	LastModEndDate     string
	SourceIdentifier   string
	Page               NVDPage
}

type NVDCVEHistoryQuery struct {
	CVEID           string
	EventName       string
	ChangeStartDate string
	ChangeEndDate   string
	Page            NVDPage
}

type NVDCPEsQuery struct {
	CPENameID        string
	CPEMatchString   string
	MatchCriteriaID  string
	LastModStartDate string
	LastModEndDate   string
	Page             NVDPage
}

type NVDCPEMatchQuery struct {
	CVEID            string
	MatchCriteriaID  string
	LastModStartDate string
	LastModEndDate   string
	Page             NVDPage
}

type NVDSourcesQuery struct {
	SourceIdentifier string
	LastModStartDate string
	LastModEndDate   string
	Page             NVDPage
}

// nvdCursor reports the cursor value to send, and whether to send one at all. An empty
// cursor is how a caller opts in on the first page, so "send an empty string" and "send
// nothing" are different requests.
func nvdCursor(p NVDPage) (string, bool) {
	if p.Cursor != "" {
		return p.Cursor, true
	}
	return "", p.StartCursor
}

// nvdError keeps the API's explanation of a refused request.
//
// The NVD-compatible endpoints answer a bad request with {"message", "status"}, naming the
// parameter at fault: a date range over 120 days, a malformed CPE, a parameter NVD has
// that is not supported yet. The SDK's own error text is only the status line, so without
// this a caller sees "400 Bad Request" and never learns what to fix.
func nvdError(op string, err error) error {
	var apiErr *vulncheck.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		if body, ok := apiErr.Model().(vulncheck.RenderNvdErrorBody); ok && body.GetMessage() != "" {
			return fmt.Errorf("%s: %w: %s", op, err, body.GetMessage())
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}

func (c *VulncheckClient) SearchNVDCVEs(ctx context.Context, q NVDCVEsQuery) (*NVDResult[vulncheck.NvdcvesNvdCveExtended], error) {
	req := c.sdk.NvdAPI.NvdCvesGet(c.authContext(ctx))
	if q.CVEID != "" {
		req = req.CveId(q.CVEID)
	}
	if q.CPEName != "" {
		req = req.CpeName(q.CPEName)
	}
	if q.IsVulnerable {
		req = req.IsVulnerable(true)
	}
	if q.VirtualMatchString != "" {
		req = req.VirtualMatchString(q.VirtualMatchString)
	}
	if q.VersionStart != "" {
		req = req.VersionStart(q.VersionStart)
	}
	if q.VersionStartType != "" {
		req = req.VersionStartType(q.VersionStartType)
	}
	if q.VersionEnd != "" {
		req = req.VersionEnd(q.VersionEnd)
	}
	if q.VersionEndType != "" {
		req = req.VersionEndType(q.VersionEndType)
	}
	if q.CVETag != "" {
		req = req.CveTag(q.CVETag)
	}
	if q.HasKEV {
		req = req.HasKev(true)
	}
	if q.NoRejected {
		req = req.NoRejected(true)
	}
	if q.PubStartDate != "" {
		req = req.PubStartDate(q.PubStartDate)
	}
	if q.PubEndDate != "" {
		req = req.PubEndDate(q.PubEndDate)
	}
	if q.LastModStartDate != "" {
		req = req.LastModStartDate(q.LastModStartDate)
	}
	if q.LastModEndDate != "" {
		req = req.LastModEndDate(q.LastModEndDate)
	}
	if q.SourceIdentifier != "" {
		req = req.SourceIdentifier(q.SourceIdentifier)
	}
	if q.Page.Limit > 0 {
		req = req.ResultsPerPage(q.Page.Limit)
	}
	if cursor, ok := nvdCursor(q.Page); ok {
		req = req.Cursor(cursor)
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, nvdError("searching NVD CVEs", err)
	}

	data := make([]vulncheck.NvdcvesNvdCveExtended, 0, len(resp.Vulnerabilities))
	for _, entry := range resp.Vulnerabilities {
		if entry.Cve != nil {
			data = append(data, *entry.Cve)
		}
	}
	return &NVDResult[vulncheck.NvdcvesNvdCveExtended]{
		Data: data, Total: int(resp.TotalResults), NextCursor: resp.GetNextCursor(),
	}, nil
}

func (c *VulncheckClient) SearchNVDCVEHistory(ctx context.Context, q NVDCVEHistoryQuery) (*NVDResult[vulncheck.RestNvdChange], error) {
	req := c.sdk.NvdAPI.NvdCveHistoryGet(c.authContext(ctx))
	if q.CVEID != "" {
		req = req.CveId(q.CVEID)
	}
	if q.EventName != "" {
		req = req.EventName(q.EventName)
	}
	if q.ChangeStartDate != "" {
		req = req.ChangeStartDate(q.ChangeStartDate)
	}
	if q.ChangeEndDate != "" {
		req = req.ChangeEndDate(q.ChangeEndDate)
	}
	if q.Page.Limit > 0 {
		req = req.ResultsPerPage(q.Page.Limit)
	}
	if cursor, ok := nvdCursor(q.Page); ok {
		req = req.Cursor(cursor)
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, nvdError("searching NVD CVE history", err)
	}

	data := make([]vulncheck.RestNvdChange, 0, len(resp.CveChanges))
	for _, entry := range resp.CveChanges {
		if entry.Change != nil {
			data = append(data, *entry.Change)
		}
	}
	return &NVDResult[vulncheck.RestNvdChange]{
		Data: data, Total: int(resp.TotalResults), NextCursor: resp.GetNextCursor(),
	}, nil
}

func (c *VulncheckClient) SearchNVDCPEs(ctx context.Context, q NVDCPEsQuery) (*NVDResult[vulncheck.NvdcpesNvdCpe], error) {
	req := c.sdk.NvdAPI.NvdCpesGet(c.authContext(ctx))
	if q.CPENameID != "" {
		req = req.CpeNameId(q.CPENameID)
	}
	if q.CPEMatchString != "" {
		req = req.CpeMatchString(q.CPEMatchString)
	}
	if q.MatchCriteriaID != "" {
		req = req.MatchCriteriaId(q.MatchCriteriaID)
	}
	if q.LastModStartDate != "" {
		req = req.LastModStartDate(q.LastModStartDate)
	}
	if q.LastModEndDate != "" {
		req = req.LastModEndDate(q.LastModEndDate)
	}
	if q.Page.Limit > 0 {
		req = req.ResultsPerPage(q.Page.Limit)
	}
	if cursor, ok := nvdCursor(q.Page); ok {
		req = req.Cursor(cursor)
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, nvdError("searching NVD CPEs", err)
	}

	data := make([]vulncheck.NvdcpesNvdCpe, 0, len(resp.Products))
	for _, entry := range resp.Products {
		if entry.Cpe != nil {
			data = append(data, *entry.Cpe)
		}
	}
	return &NVDResult[vulncheck.NvdcpesNvdCpe]{
		Data: data, Total: int(resp.TotalResults), NextCursor: resp.GetNextCursor(),
	}, nil
}

func (c *VulncheckClient) SearchNVDCPEMatch(ctx context.Context, q NVDCPEMatchQuery) (*NVDResult[vulncheck.NvdcpematchNvdMatchString], error) {
	req := c.sdk.NvdAPI.NvdCpeMatchGet(c.authContext(ctx))
	if q.CVEID != "" {
		req = req.CveId(q.CVEID)
	}
	if q.MatchCriteriaID != "" {
		req = req.MatchCriteriaId(q.MatchCriteriaID)
	}
	if q.LastModStartDate != "" {
		req = req.LastModStartDate(q.LastModStartDate)
	}
	if q.LastModEndDate != "" {
		req = req.LastModEndDate(q.LastModEndDate)
	}
	if q.Page.Limit > 0 {
		req = req.ResultsPerPage(q.Page.Limit)
	}
	if cursor, ok := nvdCursor(q.Page); ok {
		req = req.Cursor(cursor)
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, nvdError("searching NVD CPE match criteria", err)
	}

	data := make([]vulncheck.NvdcpematchNvdMatchString, 0, len(resp.MatchStrings))
	for _, entry := range resp.MatchStrings {
		if entry.MatchString != nil {
			data = append(data, *entry.MatchString)
		}
	}
	return &NVDResult[vulncheck.NvdcpematchNvdMatchString]{
		Data: data, Total: int(resp.TotalResults), NextCursor: resp.GetNextCursor(),
	}, nil
}

func (c *VulncheckClient) SearchNVDSources(ctx context.Context, q NVDSourcesQuery) (*NVDResult[vulncheck.NvdsourceNvdSource], error) {
	req := c.sdk.NvdAPI.NvdSourceGet(c.authContext(ctx))
	if q.SourceIdentifier != "" {
		req = req.SourceIdentifier(q.SourceIdentifier)
	}
	if q.LastModStartDate != "" {
		req = req.LastModStartDate(q.LastModStartDate)
	}
	if q.LastModEndDate != "" {
		req = req.LastModEndDate(q.LastModEndDate)
	}
	if q.Page.Limit > 0 {
		req = req.ResultsPerPage(q.Page.Limit)
	}
	if q.Page.StartIndex > 0 {
		req = req.StartIndex(q.Page.StartIndex)
	}

	resp, httpResp, err := req.Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, nvdError("searching NVD sources", err)
	}

	data := resp.Sources
	if data == nil {
		data = []vulncheck.NvdsourceNvdSource{}
	}
	return &NVDResult[vulncheck.NvdsourceNvdSource]{Data: data, Total: int(resp.TotalResults)}, nil
}
