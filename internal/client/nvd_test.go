package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nvdEnvelope builds an NVD API 2.0 response body around one data array.
func nvdEnvelope(dataKey string, rows []map[string]any, total int, nextCursor string) map[string]any {
	body := map[string]any{
		"resultsPerPage": len(rows),
		"startIndex":     0,
		"totalResults":   total,
		"format":         "NVD_X",
		"version":        "2.0",
		"timestamp":      "2026-10-13T00:00:00.000",
		dataKey:          rows,
	}
	if nextCursor != "" {
		body["nextCursor"] = nextCursor
	}
	return body
}

func TestSearchNVDCVEs(t *testing.T) {
	t.Run("maps query fields, unwraps records and returns the cursor", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "/rest/json/cves/2.0", r.URL.Path)
			q := r.URL.Query()
			assert.Equal(t, "CVE-2021-44228", q.Get("cveId"))
			assert.Equal(t, "true", q.Get("hasKev"))
			assert.Equal(t, "5", q.Get("resultsPerPage"))
			assert.False(t, q.Has("noRejected"), "an unset flag must not be sent")
			return jsonResp(200, nvdEnvelope("vulnerabilities", []map[string]any{
				{"cve": map[string]any{"id": "CVE-2021-44228", "vulnStatus": "Analyzed"}},
			}, 1, "tok123")), nil
		})

		result, err := vc.SearchNVDCVEs(t.Context(), NVDCVEsQuery{
			CVEID: "CVE-2021-44228", HasKEV: true, Page: NVDPage{Limit: 5},
		})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Equal(t, "CVE-2021-44228", result.Data[0].GetId())
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "tok123", result.NextCursor)
	})

	t.Run("start_cursor sends an empty cursor to opt in", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			q := r.URL.Query()
			assert.True(t, q.Has("cursor"), "the first page opts in by sending cursor")
			assert.Empty(t, q.Get("cursor"))
			return jsonResp(200, nvdEnvelope("vulnerabilities", nil, 0, "")), nil
		})
		_, err := vc.SearchNVDCVEs(t.Context(), NVDCVEsQuery{Page: NVDPage{StartCursor: true}})
		require.NoError(t, err)
	})

	t.Run("a cursor is passed through", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "tok123", r.URL.Query().Get("cursor"))
			return jsonResp(200, nvdEnvelope("vulnerabilities", nil, 0, "")), nil
		})
		_, err := vc.SearchNVDCVEs(t.Context(), NVDCVEsQuery{Page: NVDPage{StartCursor: true, Cursor: "tok123"}})
		require.NoError(t, err)
	})

	t.Run("no cursor is sent unless asked for", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.False(t, r.URL.Query().Has("cursor"))
			return jsonResp(200, nvdEnvelope("vulnerabilities", nil, 0, "")), nil
		})
		result, err := vc.SearchNVDCVEs(t.Context(), NVDCVEsQuery{CVEID: "CVE-2021-44228"})
		require.NoError(t, err)
		assert.NotNil(t, result.Data, "an empty page is an empty slice, not null")
	})

	t.Run("a refused request keeps the API's reason", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(400, map[string]any{
				"message": `parameter "keywordSearch" is not supported in v1; deferred to v2`,
				"status":  400,
			}), nil
		})
		_, err := vc.SearchNVDCVEs(t.Context(), NVDCVEsQuery{CVEID: "CVE-2021-44228"})
		require.Error(t, err)
		require.ErrorContains(t, err, "searching NVD CVEs")
		require.ErrorContains(t, err, "deferred to v2", "the message names the parameter to fix")
	})

	t.Run("an error with no body still wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.SearchNVDCVEs(t.Context(), NVDCVEsQuery{})
		require.Error(t, err)
		require.ErrorContains(t, err, "searching NVD CVEs")
	})
}

func TestSearchNVDCVEHistory(t *testing.T) {
	vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "/rest/json/cvehistory/2.0", r.URL.Path)
		q := r.URL.Query()
		assert.Equal(t, "CVE-2021-44228", q.Get("cveId"))
		assert.Equal(t, "CVE Modified", q.Get("eventName"))
		assert.Equal(t, "2026-01-01T00:00:00.000", q.Get("changeStartDate"))
		assert.Equal(t, "2026-02-01T00:00:00.000", q.Get("changeEndDate"))
		return jsonResp(200, nvdEnvelope("cveChanges", []map[string]any{
			{"change": map[string]any{
				"cveId": "CVE-2021-44228", "eventName": "CVE Modified", "cveChangeId": "x", "sourceIdentifier": "nvd@nist.gov",
				"details": []map[string]any{
					{"type": "Reference", "newValue": "https://example.com"},
					{"type": "Affected", "oldValue": []any{map[string]any{"a": 1}}, "newValue": map[string]any{"b": 2}},
				},
			}},
		}, 71, "")), nil
	})

	result, err := vc.SearchNVDCVEHistory(t.Context(), NVDCVEHistoryQuery{
		CVEID: "CVE-2021-44228", EventName: "CVE Modified",
		ChangeStartDate: "2026-01-01T00:00:00.000", ChangeEndDate: "2026-02-01T00:00:00.000",
	})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
	assert.Equal(t, "CVE-2021-44228", result.Data[0].GetCveId())
	require.Len(t, result.Data[0].Details, 2, "values of every shape decode")
	assert.Equal(t, 71, result.Total)
}

func TestSearchNVDCPEs(t *testing.T) {
	vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "/rest/json/cpes/2.0", r.URL.Path)
		assert.Equal(t, "cpe:2.3:a:apache:log4j", r.URL.Query().Get("cpeMatchString"))
		return jsonResp(200, nvdEnvelope("products", []map[string]any{
			{"cpe": map[string]any{"cpeName": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "cpeNameId": "uuid", "deprecated": false}},
		}, 162, "tok")), nil
	})

	result, err := vc.SearchNVDCPEs(t.Context(), NVDCPEsQuery{CPEMatchString: "cpe:2.3:a:apache:log4j"})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
	assert.Equal(t, "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", result.Data[0].GetCpeName())
	assert.Equal(t, 162, result.Total)
	assert.Equal(t, "tok", result.NextCursor)
}

func TestSearchNVDCPEMatch(t *testing.T) {
	vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "/rest/json/cpematch/2.0", r.URL.Path)
		assert.Equal(t, "CVE-2021-44228", r.URL.Query().Get("cveId"))
		return jsonResp(200, nvdEnvelope("matchStrings", []map[string]any{
			{"matchString": map[string]any{"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "matchCriteriaId": "mc-1", "status": "Active"}},
		}, 395, "")), nil
	})

	result, err := vc.SearchNVDCPEMatch(t.Context(), NVDCPEMatchQuery{CVEID: "CVE-2021-44228"})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
	assert.Equal(t, "mc-1", result.Data[0].GetMatchCriteriaId())
	assert.Equal(t, 395, result.Total)
}

func TestSearchNVDSources(t *testing.T) {
	t.Run("pages by start index, never by cursor", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "/rest/json/source/2.0", r.URL.Path)
			q := r.URL.Query()
			assert.Equal(t, "20", q.Get("startIndex"))
			assert.False(t, q.Has("cursor"), "/source/2.0 has no cursor")
			return jsonResp(200, nvdEnvelope("sources", []map[string]any{
				{"name": "MITRE", "sourceIdentifiers": []string{"cve@mitre.org"}},
			}, 514, "")), nil
		})

		result, err := vc.SearchNVDSources(t.Context(), NVDSourcesQuery{
			Page: NVDPage{Limit: 20, StartIndex: 20, StartCursor: true},
		})
		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		assert.Equal(t, 514, result.Total)
		assert.Empty(t, result.NextCursor)
	})

	t.Run("a refused request keeps the API's reason", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(400, map[string]any{"message": "date range exceeds 120 days", "status": 400}), nil
		})
		_, err := vc.SearchNVDSources(t.Context(), NVDSourcesQuery{})
		require.ErrorContains(t, err, "date range exceeds 120 days")
	})
}
