# Available Tools

## Response envelope

Every list-returning tool reports the same core alongside its rows, so reading an answer does
not depend on knowing which tool produced it:

| Field | Meaning |
|---|---|
| `data` | the rows — **always present**, including when empty |
| `returned` | how many rows this response carries — **always present**, including `0` |
| `total` | how many rows matched upstream; unchanged when rows are withheld for size |
| `next_cursor` | the cursor for the next page; absent when there is no next page |
| `notes` | what the API did to the query — see below |

`data` and `returned` are never omitted. An empty result is visibly empty rather than
missing, because "nothing matched" and "something went wrong" must not look the same.

`total > returned` means the rows in front of you are not the whole answer — `total` is. It
does **not** always mean a next page is reachable: `search_cpe` has no `page`, `limit` or
`cursor` argument, so its extra rows cannot be fetched through this server at all, and it
says so in `notes`. Check `notes` and `next_cursor` for the route rather than assuming one.

`search_docs` carries the core too, though it searches a locally-parsed documentation index
rather than API records, so it bounds itself and stays outside the byte budget below.

**Not yet covered:** the catalogue tools — `list_indices`, `list_backups`,
`v4_list_advisories`, `v4_list_advisory_backups` — return `{data, total}` with no `returned`
or `notes`, and are not size-bounded. `list_backups` is the one to know about: it returns all
516 backups with descriptions, about 62 KB, with no way to ask for names only. Tracked
separately from the envelope work.

Tools add fields of their own where they have something only they can report — `index` names
the index a product tool chose on your behalf, `vendors_tried` records the capitalisations
`v4_search_advisory` retried, `window` and `providers` describe a digest. These are additive;
the core above is always there.

### Notes

`notes` explains what the **API** did to a query. (What this server did to the response is
reported separately in `response_size`, below.) The ones to act on:

| Note begins | Meaning |
|---|---|
| `FILTERS NOT APPLIED` | **the answer is wrong, not merely partial** — always listed first. An index accepts only some filters, and the API ignores one it does not support instead of rejecting it, returning HTTP 200, unfiltered rows and a plausible-looking `total`. The named filter did nothing. Do not report these rows as narrowed by it. |
| `records match this query but none was returned` | an empty page with a non-zero `total`: the API filters a page *after* slicing it, so a small `limit` can yield nothing. Not an absence of data. The note ends with the remedy — **retry with a larger limit** normally, or **pass `next_cursor` back as `cursor`** when the response carries one, since enlarging the limit does not advance a walk. |
| `the cursor walk is complete` | the other reason a page is empty: you have paged to the end. `total` counts what matched upstream, not what remains, so a larger `limit` will not produce more. |
| `this tool cannot reach the rest` | `search_cpe` only: there is no `page`, `limit` or `cursor` argument, so the rows beyond the first 100 are unreachable here. Use `get_cpe_cves` with a wildcard CPE, or a backup. |
| `to reach the rest, set start_cursor` | the tool pages by cursor but only issues one when asked. |
| `these rows are one page of a larger match set` | report `total`, not the row count. |
| `this index describes a population of hosts or events` | the rows are a sample of a population rather than an enumeration. |
| `total exceeds what a single sequence of pages can reach` | 10,000 records upstream. **Cursor pagination is not subject to it** — pass `start_cursor`, then feed `next_cursor` back as `cursor`. Use a backup of the index only if you want the whole set at once. |

#### Where filter-drop detection applies

Drops are detected by comparing the filters sent against the parameter list the index
publishes with every response, so it costs no extra request. That list only exists on
`/v3/index`, so detection covers exactly five tools: **`search_index`,
`search_target_intel`, `search_ip_intel`, `search_canaries`, `search_curated_exploits`**.

**On every other tool, the absence of a `FILTERS NOT APPLIED` note is not evidence that your
filters were applied.** `search_cve`, `search_cpe`, `search_purls`, `get_cpe_cves`,
`identify_component`, `v4_search_advisory` and `list_recent_advisories` sit on endpoints that
publish no parameter list, and they cannot be checked. Their upstream endpoints fail in two
different ways, and the second is the more dangerous:

- `/v3/search/cve`, `/v3/search/cpe`, `/v3/cpe` **ignore** an unrecognised parameter and
  return HTTP 200 with the *unfiltered* set — so a result can be broader than you asked for.
- `/v4/advisory` returns **nothing**: an unrecognised parameter yields `total: 0` with a
  response byte-identical to a genuine no-match. A typo'd filter and "no advisories match"
  are indistinguishable, and the failure points at *"nothing found"* — the answer you should
  be least willing to pass on unchecked.

Two further limits on the five tools that *are* checked. A zero-row response carries no
parameter list, so it is not checked — safely, because an ignored filter can only widen a
result, so an empty answer cannot be hiding a narrower one. And a filter an index lists but
does not honour is invisible from outside.

Call `describe_index` before querying an unfamiliar index — it reports the filters that index
accepts and the values each one takes. For the tools above it is the only check available.

## Response size

Every tool that returns API records keeps its response within a byte budget — 30,000 bytes
by default, overridable at startup with `VULNCHECK_MCP_MAX_RESPONSE_BYTES`. Record sizes
vary enormously between indices, and `limit` bounds the number of records rather than their
size: the Log4Shell record on `vulncheck-nvd2` is 2.16 MB on its own, which no row count
can bound.

A response within budget is returned exactly as the API produced it, byte for byte.

Over budget, arrays are shortened — every array in the response, at any depth, to the same
length. If that is not enough, records are removed as well: as many as fit are kept, in
order, though an oversized leading record is skipped rather than allowed to hide the smaller
ones behind it. Records that are removed are named so they can be fetched individually.

Records that are returned keep every field. Their **arrays** may be shortened, and `capped`
gives each one's true length — a record returned on the row-removal path has had its arrays
cut to a single item, so no count visible in it should be reported as real.

When a response is shortened it carries a `response_size` field alongside `data` — every
tool returns a JSON object, so the report always travels with the records it describes and
cannot be read apart from them. It describes what **this server** did to fit the response,
where [`notes`](#notes) describes what the API did to the query. It reports:

| Field | Meaning |
|---|---|
| `note` | **first field** — what was done and what not to trust; read this before the records |
| `capped` | each shortened array, by JSON Pointer, and its **true length** before shortening |
| `array_limit` | the length arrays were shortened to |
| `rows_returned` | how many records were returned, when records were dropped |
| `removed_ids` | identifiers of records that did not fit, so they can be fetched individually |
| `rows_removed` | how many did not fit — `removed_ids` names at most 25 of them |
| `arrays_shortened` | how many arrays were shortened, when `capped` lists only the longest 25 |
| `outline` | for a response that cannot be shortened at all, where its weight actually sits |

A shortened array is not a short array. If `capped` reports `references` had 5,376 entries,
three entries in the response does not mean there are three. This is a **successful
result**, not an error.

Records dropped for size are not on the following page — the cursor advances past the whole
page — so use `removed_ids` to fetch them, or narrow the query.

## Indices

| Tool | Description |
|------|-------------|
| `list_indices` | List VulnCheck index names. Returns names only unless a `search` narrows the set, since the full catalogue is large; descriptions can be requested explicitly with `include_description`. |
| `describe_index` | Report which filters an index accepts, how large it is, and which tool to query it with. Call before `search_index` against an unfamiliar index — indices accept different filters, and one an index does not support has no effect rather than raising an error. |
| `search_index` | Query a VulnCheck index by name. Supports identifier, threat-intelligence and date-range filters, sorting, and cursor-based pagination (`limit` defaults to 1, maximum 200). For IP Intelligence, Target Intelligence and Canary Intelligence, prefer the dedicated product tools below. |

## Products

Tools for the flagship product indices. Each selects its own index, so no index name is needed, and each exposes the filters relevant to that product. Results are a **sample** of a matching population — `total` reports the size of the whole set — and responses are bounded by size rather than row count, as described under [Response size](#response-size).

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
| `get_cpe_cves` | Return all CVE IDs associated with a CPE 2.3 string. Optionally restrict to CVEs where the CPE is confirmed vulnerable. Any attribute accepts `*` and `?` wildcards, so a trailing wildcard on the product covers every product sharing that prefix in one call — prefer this over `search_cpe` when exploring a vendor: `search_cpe` returns at most 100 CPEs per call with no way to page to the rest, and its response can still reach tens of megabytes because each CPE carries its full CVE list. Wildcarding both vendor and product is unbounded and should be avoided. |
| `search_cpe` | Search for CPEs by component fields (vendor, product, version, part) and return matching CPEs with their associated CVEs. `vulnerable_only` narrows the CVEs listed against each CPE, **not** the CPEs returned — the row count is unchanged by it. |
| `search_purls` | Return vulnerability findings for one or more Package URLs (PURLs). Each result includes associated CVEs and vulnerability details. |
| `identify_component` | Convert a vendor, product, and optional version into best-match CPE and PURL identifiers with confidence levels. |

## Advisories (v4)

| Tool | Description |
|------|-------------|
| `list_recent_advisories` | Summarise which advisories were published or updated over a time window — the answer to "what changed recently". Returns a compact digest of identity, provenance and timing rather than full records, so a page costs a fraction of the underlying data. Defaults to the last 24 hours; optionally scoped to one feed, vendor or product. Reports which feeds the page came from, and flags when a single feed dominates it. Follow up with `v4_search_advisory` and a `cve_id` for a record in full. |
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