# Available Tools

## Indices

| Tool | Description |
|------|-------------|
| `list_indices` | List VulnCheck index names. Returns names only unless a `search` narrows the set, since the full catalogue is large; descriptions can be requested explicitly with `include_description`. |
| `describe_index` | Report which filters an index accepts, how large it is, and which tool to query it with. Call before `search_index` against an unfamiliar index — indices accept different filters, and one an index does not support has no effect rather than raising an error. |
| `search_index` | Query a VulnCheck index by name. Supports identifier, threat-intelligence and date-range filters, sorting, and cursor-based pagination. For IP Intelligence, Target Intelligence and Canary Intelligence, prefer the dedicated product tools below. |

## Products

Tools for the flagship product indices. Each selects its own index, so no index name is needed, and each exposes the filters relevant to that product. Results are a **sample** of a matching population — `total` reports the size of the whole set — and responses are bounded by size rather than row count.

Your MCP client lists the available arguments for each tool; the summaries below describe what each one answers.

| Tool | Description |
|------|-------------|
| `search_target_intel` | Find internet-facing hosts confirmed to be running vulnerable software, mapped to CVEs by version-level fingerprinting. Answers "which hosts are exposed to this CVE", and locates infrastructure by classification. Filter by CVE, software identity, network, or location. |
| `search_ip_intel` | Find attacker and target IP infrastructure over a rolling window — command-and-control servers, honeypots, and hosts potentially targeted by initial-access exploits — with geolocation and ASN enrichment. Choose the period with `window`. |
| `search_canaries` | Find exploitation attempts observed against VulnCheck's globally deployed vulnerable canary hosts. Because the canary is genuinely vulnerable, a hit is direct evidence of in-the-wild attack rather than an inference. Choose the period with `window`. |
| `search_curated_exploits` | Search curated exploit intelligence by how good the exploit is and how thoroughly it was validated, not merely whether one exists. Answers "which vulnerabilities have weaponized exploit code", "what have VulnCheck's exploit developers reviewed", and "what is in the VulnCheck KEV catalogue but not CISA's". Filter by maturity, validation level, either KEV catalogue, CVE, or a change-date range. |

## Backups

| Tool | Description |
|------|-------------|
| `list_backups` | List all VulnCheck index backups. Call this first to discover which index names can be passed to `get_backup`. Accepts an optional `search` parameter to filter by name or description. |
| `get_backup` | Return all backup links for a given index. |

## Documentation

| Tool | Description |
|------|-------------|
| `search_docs` | Search the VulnCheck documentation and return matching pages ranked by relevance, with titles, descriptions and URLs. Pass a URL to `get_doc` for the page itself. Searches every section except translations of the primary content; call without a query to list the sections. |
| `get_doc` | Fetch the raw markdown content of a VulnCheck documentation page. Use `search_docs` first to discover available page URLs. |

## CVE Search

| Tool | Description |
|------|-------------|
| `search_cve` | Search all VulnCheck indices for a CVE ID. Returns matching records aggregated across advisories, exploits, threat intelligence, and vulnerability databases. Supports cursor-based pagination. |

## CPE & PURL

| Tool | Description |
|------|-------------|
| `get_cpe_cves` | Return all CVE IDs associated with a CPE 2.3 string. Optionally restrict to CVEs where the CPE is confirmed vulnerable. Any attribute accepts `*` and `?` wildcards, so a trailing wildcard on the product covers every product sharing that prefix in one call — prefer this over `search_cpe` when exploring a vendor, because `search_cpe` returns every matching CPE and its response can reach tens of megabytes. Wildcarding both vendor and product is unbounded and should be avoided. |
| `search_cpe` | Search for CPEs by component fields (vendor, product, version, part) and return matching CPEs with their associated CVEs. |
| `search_purls` | Return vulnerability findings for one or more Package URLs (PURLs). Each result includes associated CVEs and vulnerability details. |
| `identify_component` | Convert a vendor, product, and optional version into best-match CPE and PURL identifiers with confidence levels. |

## Advisories (v4)

| Tool | Description |
|------|-------------|
| `v4_list_advisories` | List all available VulnCheck advisory feeds. Call this first to discover which advisory names can be passed to `v4_search_advisory`. |
| `v4_search_advisory` | Search VulnCheck v4 advisory feeds. Filter by advisory name, CVE ID, vendor, product, version, CPE, PURL, and more. This is the tool that finds advisories carrying no CPE data, such as GHSA records for npm, PyPI and Go software — prefer it over the CPE tools for package-ecosystem products. Vendor and product are matched exactly and case-sensitively against the CNA-published strings; alternative capitalisations are retried automatically and an unmatchable product filter is dropped, with both explained in notes. |
| `v4_list_advisory_backups` | List all VulnCheck v4 advisory backup feeds and their availability. Call this first to discover which feed names can be passed to `v4_get_advisory_backup`. |
| `v4_get_advisory_backup` | Return pre-signed download URLs for a VulnCheck v4 advisory feed backup. |

## Threat Intel

| Tool | Description |
|------|-------------|
| `list_c2_hostnames` | Retrieve the list of VulnCheck C2 hostnames. Useful for identifying command-and-control infrastructure in protective DNS services and denylists. Accepts an optional `search` parameter to look up a specific hostname. |
| `list_c2_tags` | Retrieve the list of VulnCheck C2 IP addresses. Useful for identifying command-and-control infrastructure in block lists or firewall rules. Accepts an optional `search` parameter to look up a specific IP address. |
| `get_rules` | Retrieve initial-access detection rules by type. Supported types: `suricata`, `snort`. Accepts an optional `cve` parameter to filter rules to those containing a specific CVE ID. |