package client

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// indexDoc wraps documents the way /v3/index/{name} does.
func indexDoc(docs ...any) map[string]any {
	return map[string]any{
		"_meta": map[string]any{"total_documents": len(docs)},
		"data":  docs,
	}
}

func cpeMatch(vulnerable bool, criteria string, extra map[string]any) map[string]any {
	m := map[string]any{"vulnerable": vulnerable, "criteria": criteria}
	maps.Copy(m, extra)
	return m
}

// node builds one configuration node holding the given match rules.
func node(matches ...any) map[string]any {
	return map[string]any{"cpeMatch": matches}
}

// config builds one configuration holding the given nodes.
func config(nodes ...any) map[string]any {
	return map[string]any{"nodes": nodes}
}

// newIndexTestServer serves one canned response per index name, so a test can also
// assert which index was asked.
func newIndexTestServer(t *testing.T, byIndex map[string]any, status map[string]int) *VulncheckClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v3/index/")
		if code, ok := status[key]; ok && code != http.StatusOK {
			w.WriteHeader(code)
			_, _ = fmt.Fprint(w, "failure")
			return
		}
		if body, ok := byIndex[key]; ok {
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		_ = json.NewEncoder(w).Encode(indexDoc())
	}))
	t.Cleanup(srv.Close)

	return &VulncheckClient{
		http:      srv.Client(),
		baseURL:   srv.URL,
		token:     "test-token",
		userAgent: "vulncheck-mcp/test",
	}
}

// byProduct indexes a projection by product name for order-independent assertions.
func byProduct(products []AffectedProduct) map[string]AffectedProduct {
	out := make(map[string]AffectedProduct, len(products))
	for _, p := range products {
		out[p.Product] = p
	}
	return out
}

func TestGetCVEAffectedProducts(t *testing.T) {
	t.Run("splits vulnerable products from AND-configuration platforms", func(t *testing.T) {
		// Shaped after CVE-2026-22561: an AND configuration carries the vulnerable
		// application in one node and the host OS in a sibling node.
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"id": "CVE-2026-22561",
				"configurations": []any{map[string]any{
					"operator": "AND",
					"nodes": []any{
						node(cpeMatch(
							true, "cpe:2.3:a:anthropic:claude:*:*:*:*:*:*:*:*",
							map[string]any{"versionEndExcluding": "1.1.3363"},
						)),
						node(cpeMatch(
							false, "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", nil,
						)),
					},
				}},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2026-22561")
		require.NoError(t, err)

		require.Len(t, result.Products, 1)
		assert.Equal(t, "anthropic", result.Products[0].Vendor)
		assert.Equal(t, "claude", result.Products[0].Product)
		assert.Equal(t, "a", result.Products[0].Part)
		assert.Equal(t, []string{"<1.1.3363"}, result.Products[0].Versions)
		assert.Equal(t, []string{sourceNVD}, result.Products[0].Sources)

		require.Len(t, result.Platforms, 1)
		assert.Equal(t, "microsoft", result.Platforms[0].Vendor)
		assert.Equal(t, "windows", result.Platforms[0].Product)
		assert.Equal(t, "o", result.Platforms[0].Part, "the platform is an OS, not an application")

		assert.Equal(t, 1, result.TotalProducts)
		assert.False(t, result.Truncated)
		assert.Empty(t, result.Note)
	})

	t.Run("reads vcConfigurations when configurations is absent", func(t *testing.T) {
		// CVE-2025-7195's real shape: NIST has not analysed it, so the document
		// carries no configurations key at all and VulnCheck's set is the only data.
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"id": "CVE-2025-7195",
				"vcConfigurations": []any{
					config(node(cpeMatch(true, "cpe:2.3:a:redhat:keycloak:-:*:*:*:*:*:*:*", nil))),
				},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2025-7195")
		require.NoError(t, err)

		require.Len(t, result.Products, 1)
		assert.Equal(t, "redhat", result.Products[0].Vendor)
		assert.Equal(t, "keycloak", result.Products[0].Product)
		assert.Equal(t, []string{"all versions"}, result.Products[0].Versions)
		assert.Equal(t, []string{sourceVulnCheck}, result.Products[0].Sources)
		assert.Empty(t, result.Note, "configuration data exists, so nothing should claim otherwise")
	})

	t.Run("attributes a product each source spells differently", func(t *testing.T) {
		// CVE-2024-6387: openbsd/openssh to NIST, openssh/openssh to VulnCheck.
		// Vendor/product de-duplication cannot merge these, so both must be labelled.
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{
					config(node(cpeMatch(true, "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", nil))),
				},
				"vcConfigurations": []any{
					config(node(cpeMatch(true, "cpe:2.3:a:openssh:openssh:9.6:*:*:*:*:*:*:*", nil))),
				},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2024-6387")
		require.NoError(t, err)

		require.Len(t, result.Products, 2)
		assert.Equal(t, "openbsd", result.Products[0].Vendor)
		assert.Equal(t, []string{sourceNVD}, result.Products[0].Sources)
		assert.Equal(t, "openssh", result.Products[1].Vendor)
		assert.Equal(t, []string{sourceVulnCheck}, result.Products[1].Sources)
	})

	t.Run("merges a product both sources agree on, naming both", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{
					config(node(cpeMatch(true, "cpe:2.3:a:v:agreed:1.0:*:*:*:*:*:*:*", nil))),
				},
				"vcConfigurations": []any{
					config(node(cpeMatch(true, "cpe:2.3:a:v:agreed:2.0:*:*:*:*:*:*:*", nil))),
				},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00009")
		require.NoError(t, err)

		require.Len(t, result.Products, 1)
		assert.Equal(t, []string{"1.0", "2.0"}, result.Products[0].Versions)
		assert.Equal(t, []string{sourceNVD, sourceVulnCheck}, result.Products[0].Sources)
	})

	t.Run("renders version bounds and wildcards", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{config(node(
					cpeMatch(true, "cpe:2.3:a:v:ranged:*:*:*:*:*:*:*:*", map[string]any{
						"versionStartIncluding": "2.0", "versionEndExcluding": "2.5",
					}),
					cpeMatch(true, "cpe:2.3:a:v:exclusive:*:*:*:*:*:*:*:*", map[string]any{
						"versionStartExcluding": "1.0", "versionEndIncluding": "1.9",
					}),
					cpeMatch(true, "cpe:2.3:a:v:wildcard:*:*:*:*:*:*:*:*", nil),
					cpeMatch(true, "cpe:2.3:a:v:pinned:3.1.4:*:*:*:*:*:*:*", nil),
				))},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00002")
		require.NoError(t, err)

		got := byProduct(result.Products)
		assert.Equal(t, []string{">=2.0 <2.5"}, got["ranged"].Versions)
		assert.Equal(t, []string{">1.0 <=1.9"}, got["exclusive"].Versions)
		assert.Equal(t, []string{"all versions"}, got["wildcard"].Versions)
		assert.Equal(t, []string{"3.1.4"}, got["pinned"].Versions)
	})

	t.Run("unescapes punctuation in CPE values", func(t *testing.T) {
		// CVE-2018-0171's real version string. Common on Cisco and Juniper records.
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{config(node(
					cpeMatch(true, "cpe:2.3:o:cisco:ios:15.2\\(5\\)e:*:*:*:*:*:*:*", nil),
				))},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2018-0171")
		require.NoError(t, err)
		require.Len(t, result.Products, 1)
		assert.Equal(t, []string{"15.2(5)e"}, result.Products[0].Versions)
	})

	t.Run("an escaped colon does not shift the fields after it", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{config(node(
					cpeMatch(true, "cpe:2.3:a:v:p:1.0\\:beta:*:*:*:*:*:*:*", nil),
				))},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00010")
		require.NoError(t, err)
		require.Len(t, result.Products, 1)
		assert.Equal(t, "v", result.Products[0].Vendor)
		assert.Equal(t, "p", result.Products[0].Product)
		assert.Equal(t, []string{"1.0:beta"}, result.Products[0].Versions)
	})

	t.Run("negated scopes are not reported as affected", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{
					map[string]any{
						"negate": true,
						"nodes":  []any{node(cpeMatch(true, "cpe:2.3:a:v:negated-config:1.0:*:*:*:*:*:*:*", nil))},
					},
					config(
						map[string]any{
							"negate":   true,
							"cpeMatch": []any{cpeMatch(true, "cpe:2.3:a:v:negated-node:1.0:*:*:*:*:*:*:*", nil)},
						},
						node(cpeMatch(true, "cpe:2.3:a:v:kept:1.0:*:*:*:*:*:*:*", nil)),
					),
				},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00011")
		require.NoError(t, err)
		require.Len(t, result.Products, 1)
		assert.Equal(t, "kept", result.Products[0].Product)
	})

	t.Run("de-duplicates a product repeated across configurations", func(t *testing.T) {
		repeated := config(node(cpeMatch(true, "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", nil)))
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{repeated, repeated},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00003")
		require.NoError(t, err)
		require.Len(t, result.Products, 1)
		assert.Equal(t, []string{"1.0"}, result.Products[0].Versions)
	})

	t.Run("both configuration sets empty returns an explanatory note", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"id": "CVE-2099-99999", "configurations": nil, "vcConfigurations": nil,
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-99999")
		require.NoError(t, err)
		assert.Empty(t, result.Products)
		assert.NotNil(t, result.Products, "empty list must serialize as [] rather than null")
		assert.Contains(t, result.Note, "vcConfigurations",
			"the note must say which sources were checked")
	})

	t.Run("no document for the CVE returns the same note", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{"vulncheck-nvd2": indexDoc()}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00012")
		require.NoError(t, err)
		assert.Empty(t, result.Products)
		assert.NotEmpty(t, result.Note)
	})

	t.Run("counts criteria it could not parse", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{config(node(
					cpeMatch(true, "not-a-cpe", nil),
					cpeMatch(true, "cpe:2.3:a:truncated", nil),
					cpeMatch(true, "cpe:2.3:a:good:product:1.0:*:*:*:*:*:*:*", nil),
				))},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00008")
		require.NoError(t, err)
		require.Len(t, result.Products, 1)
		assert.Equal(t, "good", result.Products[0].Vendor)
		assert.Equal(t, 2, result.SkippedCriteria)
	})

	t.Run("configurations present but nothing usable says so", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{config(node(cpeMatch(true, "not-a-cpe", nil)))},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00013")
		require.NoError(t, err)
		assert.Empty(t, result.Products)
		assert.Equal(t, 1, result.SkippedCriteria)
		assert.Contains(t, result.Note, "skipped_criteria")
	})

	t.Run("truncates past the cap but reports the true total", func(t *testing.T) {
		matches := make([]any, 0, maxAffectedEntries+10)
		for i := range maxAffectedEntries + 10 {
			matches = append(matches, cpeMatch(true,
				fmt.Sprintf("cpe:2.3:a:vendor%03d:product:1.0:*:*:*:*:*:*:*", i), nil))
		}
		vc := newIndexTestServer(t, map[string]any{
			"vulncheck-nvd2": indexDoc(map[string]any{
				"configurations": []any{config(node(matches...))},
			}),
		}, nil)

		result, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00005")
		require.NoError(t, err)
		assert.Len(t, result.Products, maxAffectedEntries)
		assert.Equal(t, maxAffectedEntries+10, result.TotalProducts)
		assert.True(t, result.Truncated)
	})

	t.Run("an index failure is reported rather than read as no data", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{"vulncheck-nvd2": indexDoc()},
			map[string]int{"vulncheck-nvd2": http.StatusUnauthorized})

		_, err := vc.GetCVEAffectedProducts(t.Context(), "CVE-2099-00007")
		require.Error(t, err)
		assert.ErrorContains(t, err, cveAffectedIndex)
	})

	t.Run("empty cve is rejected", func(t *testing.T) {
		vc := newIndexTestServer(t, map[string]any{}, nil)
		_, err := vc.GetCVEAffectedProducts(t.Context(), "")
		require.ErrorIs(t, err, ErrNoCVEArg)
	})
}
