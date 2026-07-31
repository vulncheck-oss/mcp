package server

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var tools = []func(*mcp.Server, client.Client){
	// v3/index
	registerListIndices,
	registerSearchIndex,
	// v3/backups
	registerListBackups,
	registerGetBackup,
	// v3/cpe
	registerGetCPECVEs,
	// v3/search/cpe
	registerSearchCPE,
	// v3/purls
	registerSearchPURLs,
	// v3/identify
	registerIdentifyComponent,
	// v3/rules
	registerGetRules,
	// v3/search/cve
	registerSearchCVE,
	// docs
	registerSearchDocs,
	registerGetDoc,
	// v3/tags
	registerListC2Tags,
	// v3/pdns
	registerListC2Hostnames,
	// v4/advisory
	registerListAdvisories,
	registerSearchAdvisory,
	// v4/backup
	registerListAdvisoryBackups,
	registerGetAdvisoryBackup,
}

// adds a sufficiency signal (search_cve already aggregates the category data)
// and narrows the search_index carve-out to explicit raw-record requests
const serverInstructions = `For CVE questions, use search_cve as the default tool — it already aggregates advisories, exploits, threat intelligence, and KEV status across all indices, so a question mentioning those categories is fully answered by search_cve alone. ` +
	`Do not autonomously paginate, or call search_index to cross-check, enrich, or gather a category of data. ` +
	`Call search_index only when the user explicitly asks to query a specific named index for its raw record (e.g. "show me the NVD2 record", "query the vulncheck-kev index directly"). ` +
	`When the user explicitly asks for more results or the next page, paginate using the cursor.`

func New(vc client.Client, version string, cache *mcp.SchemaCache) *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "vulncheck", Version: version},
		&mcp.ServerOptions{SchemaCache: cache, Instructions: serverInstructions},
	)
	for _, register := range tools {
		register(srv, vc)
	}
	return srv
}
