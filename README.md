<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# vgi-threatintel

[![CI](https://github.com/Query-farm/vgi-threatintel/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-threatintel/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker, written in **Go**, that enriches cyber
**indicators of compromise** (IPs, domains, URLs, file hashes) against
threat-intelligence **reputation** sources and classifies them offline — all
exposed as DuckDB/SQL functions. It is a **defensive SOC / threat-hunting**
tool, intended for **AUTHORIZED** use, and composes naturally with sibling
workers (`vgi-ioc`, `vgi-cve`, `vgi-yara`, `vgi-sigma`).

Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK; speaks the
VGI protocol over stdio. Catalog name: `threatintel`.

```sql
INSTALL vgi FROM community; LOAD vgi;

-- LOCATION is the path to the compiled worker binary.
ATTACH 'threatintel' AS threatintel (TYPE vgi, LOCATION '/path/to/vgi-threatintel-worker');

-- Offline indicator typing / triage (no network):
SELECT threatintel.indicator_type('1.2.3.4');        -- ipv4
SELECT threatintel.indicator_type('evil.example');   -- domain
SELECT threatintel.is_private_ip('10.0.0.1');        -- true  (skip the lookup)
SELECT threatintel.is_private_ip('8.8.8.8');         -- false

-- Reputation lookup against a threat-intel source:
SELECT indicator, type, malicious, score, categories, source, last_seen
FROM threatintel.reputation('185.220.101.1');
```

## Functions

### Offline scalars (no API, no key, deterministic)

| Function | Signature | Description |
| -------- | --------- | ----------- |
| `indicator_type(value)` | `VARCHAR → VARCHAR` | Classify an indicator as `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, or **NULL** if unrecognized. |
| `is_private_ip(value)`  | `VARCHAR → BOOLEAN` | True if `value` is a private/reserved IP (RFC1918, loopback, link-local, CGNAT, TEST-NET, ULA, …). **False for non-IPs**, so `NOT is_private_ip(x)` is a safe public-lookup gate. |

These let a SOC pipeline triage cheaply before spending reputation-API budget:
type each indicator and skip lookups for internal/RFC1918 addresses.

### Reputation table function (network)

| Function | Returns | Description |
| -------- | ------- | ----------- |
| `reputation(indicator)` | `(indicator VARCHAR, type VARCHAR, malicious BOOLEAN, score DOUBLE, categories VARCHAR[], source VARCHAR, last_seen VARCHAR)` | Look up **one** indicator; **at most one** verdict row. |

Named options (all optional):

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `base_url`   | a documented reputation endpoint (see below) | Override the reputation API base URL. |
| `api_key`    | _(empty)_ | API key/token for the source, if it requires one. Sent as `X-API-Key`. |
| `timeout_ms` | `15000` | Per-request HTTP timeout in milliseconds. |

`reputation()` triages before it spends a network call: a **private/reserved
IP** or an **unsupported indicator** returns **zero rows** (no error); an
**unknown** but well-formed indicator (source 404) also returns **zero rows**.
HTTP `4xx`/`5xx`/`429` and malformed JSON surface as a **clear error** (the call
never crashes or hangs).

## Pluggable, normalized reputation source

The worker is deliberately decoupled from any one feed. It speaks a **simple
normalized reputation JSON** over `GET {base_url}?indicator=<value>`:

```json
{
  "indicator": "185.220.101.1",
  "type": "ipv4",
  "malicious": true,
  "score": 91.5,
  "categories": ["c2", "tor-exit", "scanner"],
  "source": "demo-feed",
  "last_seen": "2026-06-01T12:00:00Z"
}
```

- `score` is optional (`null`/omitted → SQL `NULL`).
- `type` is optional; if absent, the worker fills it from `indicator_type()`.
- A `404` means "unknown indicator" → no rows.

**Real feeds plug in behind this same interface via a thin adapter** that maps
the feed's response into the JSON above. Each real source has its own shape,
auth, and rate-limit/terms — you supply your **own key** and accept the source's
**terms of use**:

| Source | Auth | Notes |
| ------ | ---- | ----- |
| **OTX AlienVault** | `X-OTX-API-KEY` header | Free key; per-indicator "pulses"/reputation; map `pulse_info`/`reputation` → `malicious`/`categories`. |
| **abuse.ch URLhaus / ThreatFox** | Auth key (free, required since 2024) | URL/host/hash focus; map `query_status`/`threat`/`tags` → `malicious`/`categories`. Respect non-commercial terms. |
| **VirusTotal** | `x-apikey` header | Strict free-tier rate limits (e.g. 4 req/min); map `last_analysis_stats.malicious > 0` → `malicious`. |

The shipped default `base_url` points at a documented normalized endpoint shape
(`https://reputation.example/reputation`) rather than a specific provider,
because no major public feed is both key-free and redistribution-clean — wire in
an adapter (or the mock) for real use.

> **Authorized use only.** This tool is for defensive security work —
> threat hunting, alert triage, and IoC enrichment on infrastructure and data
> you are authorized to assess. Honor each upstream feed's API terms and rate
> limits.

## Batch / per-row enrichment

DuckDB does **not** support `LATERAL` *column* parameters over a VGI table
function — table-function arguments must be **literals**. So enrich a column of
indicators in two steps:

1. **Triage in SQL** with the offline scalars to shortlist the indicators worth
   a lookup:

   ```sql
   SELECT value FROM iocs
   WHERE threatintel.indicator_type(value) IS NOT NULL
     AND NOT threatintel.is_private_ip(value);
   ```

2. **Look up each shortlisted indicator** with a literal argument — either one
   `reputation('<value>', …)` statement per value driven from the host
   application in a loop, or `UNION ALL` over the literals:

   ```sql
   SELECT * FROM threatintel.reputation('185.220.101.1') 
   UNION ALL
   SELECT * FROM threatintel.reputation('malware-c2.example');
   ```

## Build & test

```sh
go build ./... && go vet ./... && gofmt -l . && go test ./...   # build + unit
make test-sql                                                   # SQL E2E (haybarn + mock feed)
```

`make test-sql` builds the worker and the mock reputation server, starts the
mock on a free port, points the worker's `base_url` at it via
`VGI_THREATINTEL_TEST_URL`, runs the haybarn SQL suite, and tears the mock down.
It needs `haybarn-unittest` on `PATH`:

```sh
uv tool install haybarn-unittest
export PATH="$HOME/.local/bin:$PATH"
```

## Layout

```
cmd/vgi-threatintel-worker/main.go   stdio entry point; assembles worker + catalog
cmd/mockserver/main.go               standalone mock reputation server for the E2E
internal/threatworker/indicator.go   offline IoC typing + private-IP ranges
internal/threatworker/client.go      normalized reputation HTTP client
internal/threatworker/functions.go   VGI scalar + table function registrations
internal/mockrep/                    embedded mock reputation feed (unit + E2E)
test/sql/                            haybarn SQL end-to-end tests
```

## License

The worker source is licensed under the **MIT License** — see [`LICENSE`](./LICENSE).
The `vgi-go` SDK is MIT-licensed by Query Farm LLC.

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm

