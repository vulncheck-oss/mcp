# Available Tools

## Indices

| Tool | Description |
|------|-------------|
| `list_indices` | List all VulnCheck indices. Call this first to discover which index names can be passed to `search_index`. Accepts an optional `search` parameter to filter by name or description. |
| `search_index` | Query a VulnCheck index by name. Supports optional CVE filter and cursor-based pagination. |

## Backups

| Tool | Description |
|------|-------------|
| `list_backups` | List all VulnCheck index backups. Call this first to discover which index names can be passed to `get_backup`. Accepts an optional `search` parameter to filter by name or description. |
| `get_backup` | Return all backup links for a given index. |

## Documentation

| Tool | Description |
|------|-------------|
| `search_docs` | Fetch the VulnCheck documentation index. Returns a list of all available documentation pages and their URLs. Use `get_doc` to retrieve the content of a specific page. |
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