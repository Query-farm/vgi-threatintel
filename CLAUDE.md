# CLAUDE.md — vgi-threatintel

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion. This worker is modeled
on [`vgi-cve`](https://github.com/Query-farm/vgi-cve) and
[`vgi-fhir`](https://github.com/Query-farm/vgi-fhir) — the reference Go VGI
workers — with the same tooling, layout, and SDK conventions.

## What this is

A [VGI](https://query.farm) worker (Go) that enriches cyber **indicators**
(IPs, domains, URLs, file hashes) against a threat-intel **reputation** source
and classifies them **offline**, exposed as DuckDB SQL functions. Defensive
SOC / threat-hunting tool, for **AUTHORIZED** use. Built on the
[`vgi-go`](https://github.com/Query-farm/vgi-go) SDK over stdio. Catalog name:
`threatintel`. Composes with `vgi-ioc` / `vgi-cve` / `vgi-yara` / `vgi-sigma`.

## Layout

```
cmd/vgi-threatintel-worker/main.go   stdio entry point; assembles worker + catalog
cmd/mockserver/main.go               standalone mock reputation server for the SQL E2E
internal/threatworker/indicator.go   offline typing (IndicatorType / IsPrivateIP)
internal/threatworker/client.go      normalized reputation HTTP client (net/http + encoding/json)
internal/threatworker/functions.go   VGI scalar + table function registrations
internal/mockrep/server.go,data.go   embedded mock reputation feed (shared by unit + E2E)
test/sql/*.test                      haybarn SQL end-to-end tests
```

## Go SDK pattern (reused exactly)

- `vgi.NewWorker(...)` → `w.RegisterScalar(...)` / `w.RegisterTable(...)` →
  `w.RunStdio()`. See `cmd/vgi-threatintel-worker/main.go` and
  `threatworker.Register`.
- **Offline scalars** implement `vgi.ScalarFunction` directly
  (`Name`/`Metadata`/`ArgumentSpecs`/`OnBind`/`Process`). `is_private_ip` maps a
  column with `vgi.MapColumn`; `indicator_type` builds the output array by hand
  so an unrecognized indicator (or NULL input) emits **SQL NULL** rather than
  `""`.
- **Table function** uses the typed path: `vgi.TypedTableFunc[S]` +
  `vgi.AsTableFunction[S]`. Args come from a tag struct via
  `vgi.DeriveArgSpecs` / `vgi.BindArgs`. Tag conventions:
  - `vgi:"pos=0,..."` → positional argument (the indicator).
  - `vgi:"name=base_url,default=,..."` → a **named** option (a `default=` with
    no `pos` makes it named). `api_key` and `timeout_ms` (int64, `default=15000`)
    are named too.

## gob-state gotcha (read before touching the table fn)

The SDK gob-encodes table-function state between `NewState` and `Process` (it
may cross a process boundary). State structs must hold **only exported,
gob-encodable fields** — no `arrow.Record`, no interfaces/channels/funcs, no
unexported fields. So:

- `NewState` fetches the verdict eagerly and stores a plain `[]RepRow` slice plus
  an embedded `emitState{ Done bool }`.
- `Process` rebuilds the Arrow batch from that slice and emits once, then
  `Finish`es.

`TestRegisterDoesNotPanic` exercises the SDK's gob-encodability check; keep it.

### Building the `categories VARCHAR[]` column

`reputation` returns a `List<String>` column. Build it with
`array.NewListBuilder(mem, arrow.BinaryTypes.String)`: `Append(true)` once per
row, then push each element through `lb.ValueBuilder().(*array.StringBuilder)`.
`score DOUBLE` is nullable — a nil `*float64` → `AppendNull()` → SQL NULL.

## Normalized-source / pluggable design

The worker does **not** hard-code any one feed. It speaks a **simple normalized
reputation JSON** over `GET {base_url}?indicator=<value>` (`RepResponse` in
`client.go`): `{indicator, type, malicious, score?, categories[], source,
last_seen}`. A `404` = unknown indicator → `(nil, nil)` → zero rows.

Real feeds (OTX AlienVault, abuse.ch URLhaus/ThreatFox, VirusTotal) plug in
behind this same `GET` interface via a thin **adapter** that maps the feed's
response into `RepResponse`. Each needs its **own key** and has its own
auth/rate-limit/terms (documented in `README.md`). Keep provider-specific JSON
out of the worker core; add adapters, not special cases.

### Robustness contract

- Private/reserved IP or unsupported indicator → **0 rows, no error** (triaged
  in `NewState` before any network call — don't waste lookups on internal IPs).
- Unknown indicator (source 404) → **0 rows, no error**.
- `401`/`403` (auth), `429` (rate limit), other `4xx`/`5xx`, malformed JSON →
  **clear error** surfaced to DuckDB. Never crash or hang (every request is
  bounded by `timeout_ms`).

## Mock reputation server + SQL E2E

`internal/mockrep` is an embedded HTTP server serving the normalized JSON keyed
on `?indicator=`: known-malicious IP/domain/hash (malicious=true + score +
categories), known-clean ones (malicious=false), `404` for unknown, and — when
constructed with a key — `401` unless `X-API-Key` matches. It backs both the Go
unit tests (`httptest`) and the standalone `cmd/mockserver` (prints `PORT:<n>`).

`make test-sql` (see `Makefile`) builds both binaries, starts the mock on a free
port, exports `VGI_THREATINTEL_WORKER` + `VGI_THREATINTEL_TEST_URL`, runs
`haybarn-unittest`, and `trap`-kills the mock on exit.

haybarn notes:
- `require vgi` is **silently SKIPPED** by haybarn — use `statement ok` +
  `LOAD vgi;` instead.
- Test files use `# group: [vgi_threatintel]`, `require-env
  VGI_THREATINTEL_WORKER`, and
  `ATTACH 'threatintel' AS threatintel (TYPE vgi, LOCATION '${VGI_THREATINTEL_WORKER}');`.

## Known DuckDB limitation: no LATERAL over a table function

DuckDB rejects `LATERAL` **column** parameters to a VGI table function
("does not support lateral join column parameters … only supports literals").
So batch enrichment is: (1) triage a column with the offline scalars, then
(2) call `reputation('<literal>', …)` per indicator (host-driven loop or
`UNION ALL`). The E2E (`test/sql/reputation_api.test`) demonstrates exactly this.

## Build & test

```sh
go build ./... && go vet ./... && gofmt -l . && go test ./...
make test-sql   # needs haybarn-unittest on PATH (uv tool install haybarn-unittest)
```
