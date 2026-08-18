package server

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var tools = []func(*mcp.Server, client.Client){
	// v3/index
	registerListIndices,
	registerSearchIndex,
	// v3/index — flagship product wrappers
	registerSearchTargetIntel,
	registerSearchIPIntel,
	registerSearchCanaries,
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

// serverInstructions routes tool choice by the subject of the question.
//
// search_cve aggregates a broad set of indices spanning advisories, exploits,
// threat intelligence and KEV, but it reaches none of the Target Intelligence, IP
// Intelligence or Canary Intelligence indices. Those three hold the only data that answers exposure and
// observed-attack questions, so the blanket search_index prohibition added for
// #39 — to stop clients autonomously fanning out — has to name them as
// exceptions. Without that, a question about internet exposure or in-the-wild
// exploitation is answered from indices carrying no such data, and answered
// confidently.
//
// Only the cve and date filters reach these indices today. The index-specific
// filters they also accept upstream (asn, cidr, country, vendor, product, port,
// classifications, src_country, ...) are not yet exposed by search_index; they
// arrive with the dedicated product tools.
const serverInstructions = `Route by what the question is about.

CVE metadata — severity, exploit availability and maturity, KEV status, advisories, threat actor, ransomware and botnet association: use search_cve. It aggregates these categories across many indices and is normally sufficient on its own. Do not call search_index to cross-check or enrich what it returns.

Internet exposure and observed attack activity: search_cve does not cover these. Use search_index against the index that holds the data:
- target-intel — internet-facing hosts confirmed to be running vulnerable software. Answers "which hosts are exposed to this CVE".
- ipintel-3d, ipintel-10d, ipintel-30d, ipintel-90d — attacker and target IP infrastructure: C2, honeypots and initial-access targets over a rolling window.
- vulncheck-canaries, or vulncheck-canaries-3d, -10d, -30d, -90d for a recent window — exploitation attempts observed against VulnCheck's own deliberately vulnerable canary hosts. Answers "is this CVE being exploited in the wild, and by whom".

These three describe populations of hosts and events rather than one record per CVE. Pass an explicit limit, because the default of 1 is not a meaningful answer to a population question. Read the population size from the response total and report that, rather than counting the rows returned. Do not paginate in order to enumerate them.

Otherwise call search_index only when the user explicitly asks for a specific named index's raw record, e.g. "show me the NVD2 record".

Do not paginate autonomously. When the user asks for more results or the next page, use the cursor.`

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
