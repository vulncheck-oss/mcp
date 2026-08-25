package server

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
)

var tools = []func(*mcp.Server, client.Client){
	// v3/index
	registerListIndices,
	registerDescribeIndex,
	registerSearchIndex,
	// v3/index — flagship product wrappers
	registerSearchTargetIntel,
	registerSearchIPIntel,
	registerSearchCanaries,
	registerSearchCuratedExploits,
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
	registerListRecentAdvisories,
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
// #39 — to stop clients autonomously fanning out — has to name the product tools
// that wrap them as exceptions. Without that, a question about internet exposure
// or in-the-wild exploitation is answered from indices carrying no such data, and
// answered confidently.
//
// The raw index names are deliberately absent: the product tools expose filters
// search_index does not, so naming the indices here would advertise the worse path.
//
// The split between search_cve and search_curated_exploits is by the direction of the
// question rather than by subject. Both concern exploit maturity and KEV status, but
// search_cve reports them for a CVE the caller names while search_curated_exploits
// selects CVEs by them. Describing that boundary as a topic — "use search_cve for
// maturity" — sent every "which CVEs are weaponized" question to the one tool that
// cannot filter on it.
const serverInstructions = `Route by what the question is about.

What is known about a named CVE — severity, whether exploits exist and how mature they are, KEV status, advisories, threat actor, ransomware and botnet association: use search_cve. It aggregates these categories across many indices and is normally sufficient on its own. Do not call search_index to cross-check or enrich what it returns.

Which CVEs have a given exploit property, rather than what is true of one CVE: use search_curated_exploits. search_cve reports maturity and KEV status for a CVE you name, but cannot select by them, so it cannot answer "which vulnerabilities have weaponized exploit code", "what has VulnCheck's own exploit developers reviewed", "what is in the VulnCheck KEV catalogue but not CISA's", or "which of those changed this week".

Internet exposure and observed attack activity: search_cve does not cover these. Use the product tool that owns the data:
- search_target_intel — internet-facing hosts confirmed to be running vulnerable software. Answers "which hosts are exposed to this CVE", and locates C2, scanners, proxies and honeypots by classification.
- search_ip_intel — attacker and target IP infrastructure over a rolling window: C2, honeypots and initial-access targets, with geolocation and ASN.
- search_canaries — exploitation attempts observed against VulnCheck's own deliberately vulnerable canary hosts. Answers "is this CVE being exploited in the wild, and by whom".

These three describe populations of hosts and events rather than one record per CVE. They return a sample, and total reports the size of the whole matching set — report total rather than counting the rows returned, and do not paginate in order to enumerate them.

Otherwise call search_index only when the user explicitly asks for a specific named index's raw record, e.g. "show me the NVD2 record".

Do not paginate autonomously. When the user asks for more results or the next page, use the cursor.

Responses are bounded. The tools that search and return records keep their responses within a byte budget, and when one has to be shortened the response carries a response_size field saying so. It reports which arrays were shortened and their true lengths, how many records were returned out of how many were on the page, and the identifiers of records that did not fit. The catalogue and raw-text tools are not bounded this way.

Read it. A shortened array is not a short array: if it reports references had 2457 entries, do not answer that there are five. A shortened response is a successful result, not an error — every record it contains keeps all of its fields, and only the length of its arrays and the number of records may have changed.

To recover what was left out: fetch the named records individually by their identifier, narrow the query, or for a single oversized record use the API or CLI, which are not bounded this way.`

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
