package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCPECVEs(t *testing.T) {
	t.Run("returns CVEs with total", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Contains(t, r.URL.Path, "/v3/cpe")
			assert.Equal(t, "cpe:2.3:a:microsoft:office:2016:*", r.URL.Query().Get("cpe"))
			assert.Empty(t, r.URL.Query().Get("isVulnerable"))
			return jsonResp(200, map[string]any{
				"data":  []string{"CVE-2021-44228"},
				"_meta": map[string]any{"total_documents": 1},
			}), nil
		})
		result, err := vc.GetCPECVEs(t.Context(), "cpe:2.3:a:microsoft:office:2016:*", false)
		require.NoError(t, err)
		assert.Equal(t, []string{"CVE-2021-44228"}, result.CVEs)
		assert.Equal(t, 1, result.Total)
	})

	t.Run("sets is_vulnerable param when requested", func(t *testing.T) {
		vc := newSDKTestClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "true", r.URL.Query().Get("isVulnerable"))
			return jsonResp(200, map[string]any{"data": []string{}}), nil
		})
		_, err := vc.GetCPECVEs(t.Context(), "cpe:2.3:a:foo:bar:1.0:*", true)
		require.NoError(t, err)
	})

	t.Run("nil data normalized to empty slice", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return jsonResp(200, map[string]any{}), nil
		})
		result, err := vc.GetCPECVEs(t.Context(), "cpe:2.3:a:x:y:1:*", false)
		require.NoError(t, err)
		assert.Empty(t, result.CVEs)
		assert.Equal(t, 0, result.Total)
	})

	t.Run("SDK error wraps with context", func(t *testing.T) {
		vc := newSDKTestClient(func(_ *http.Request) (*http.Response, error) {
			return errResp(500), nil
		})
		_, err := vc.GetCPECVEs(t.Context(), "cpe:2.3:a:x:y:1:*", false)
		require.Error(t, err)
		assert.ErrorContains(t, err, "getting CPE CVEs")
	})
}
