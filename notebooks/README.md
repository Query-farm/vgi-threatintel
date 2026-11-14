# Threat-intelligence triage notebook

[Triage, reputation and unknowns](01_triage_reputation_and_unknowns.ipynb) classifies invented event indicators, requests distinct eligible reputations, and keeps missing verdicts separate from negative verdicts and positive verdicts without scores. The experiment changes only a review-queue threshold.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/). The notebook uses Python 3.13 or 3.14 and a locked Haybarn 2.0.0rc11 environment. First use needs network access for Python dependencies, the published VGI extension and the pinned worker release. Subsequent analysis uses only a disposable local fixture. No Go compiler, worker checkout or locally built binary is needed; this directory can be copied alone.

```bash
uv sync --frozen
uv run --frozen python execute.py
```

Visible SQL attaches `github-auto://Query-farm/vgi-threatintel@v0.4.0`. Actual release startup was verified on macOS arm64. Published assets also cover Linux amd64/arm64 and Windows amd64, which were not executed here. Rerun the default and experiment after updating the release or environment pin.

For interactive use, register this environment and select it in Jupyter:

```bash
uv run --frozen python -m ipykernel install --user --name vgi-threatintel-notebooks --display-name 'Python (threatintel notebooks)'
```

Restart and run all after changing `MIN_SCORE`. Parameters, connection SQL and analytical SQL are visible; Python setup, plotting, interpretation source and cleanup are folded. The runner uses a temporary kernel and this directory as cwd, writes only successful outputs, and rejects unknown parameters, overrides without a separate destination, and source-directory output destinations.

## Synthetic data and supported source interface

[feed.json](fixtures/feed.json) contains six hand-invented normalized verdicts with fixed `last_seen` timestamps of 2026-01-15 12:00 UTC. Reserved `.example` names and a repeated-character SHA-256 are illustrative identifiers, not observed threats. Twelve SQL event rows include a duplicate, a private address, a documentation-range address, malformed text and a null input. No listed indicator is contacted or scanned.

[local_feed.py](local_feed.py) serves the worker's documented normalized HTTP interface on loopback. `base_url` points explicitly at this local fixture. Unknown `unknown.example` returns HTTP 404; other rows deliberately include positive/negative verdicts and a null score. This is a synthetic fixture, not captured provider data. It needs no key and has no live mode. The worker's default endpoint is a placeholder, not a public feed. Real providers require their own normalized adapter, credentials and terms; none is used here.

The two offline scalars are actual worker calls. `is_private_ip` recognizes private/reserved **IP literals**; it does not resolve domains or inspect addresses inside URLs. False for a non-IP does not establish safety. Indicator typing is lexical and does not validate content. Recognized-type and private-IP tests are combined before lookup.

This release requires literal table-function arguments; it does not accept a LATERAL indicator column. Seven explicit calls match the distinct eligible inputs and are materialized once with visible CTAS before display queries. A left join preserves original event IDs, duplicate observations and nulls. Provider `malicious` stays distinct from the local review policy. HTTP errors other than unknown/404 must surface as errors, not negative verdicts.

## Focused experiment

```bash
uv run --frozen python execute.py --parameters '{"MIN_SCORE":90}' --output-dir validation/stricter-threshold
```

Default `MIN_SCORE` is 70; accepted integers are 0–100. A review candidate needs both a positive verdict and a nonnull score at or above the threshold. The fixture score is an invented 0–100 ordering, not a probability or portable vendor scale. Raising the threshold to 90 removes positive scored indicators in `[70,90)` from the queue. Compare both event counts and distinct indicators; the duplicate contributes more than once to event volume. Raw provider verdicts, scores, unknowns and unscored positives must remain unchanged. Restore 70 for the baseline.

The coverage chart retains every event and reason; the score chart includes only distinct indicators with numeric scores. Null scores are not plotted as zero. Twelve SQL invariants cover identities, type agreement, eligibility, missing values, thresholds and accounting; journal checks confirm that only the eligible indicator set reaches the local endpoint. These checks demonstrate integration and data handling, not detection accuracy or true risk.

Saved outputs include both charts. Logs, chart PNGs and experiment copies are ignored under `validation/`; experiments include branding, fixtures, helpers and environment companions. [STANDARD.md](STANDARD.md) records presentation conventions.

Source checks passed: 20 Go tests, `go build ./...`, `go vet ./...`, clean `gofmt -l`, and 87 SQL assertions in two cases using the supported Haybarn unittest runner with the repository's mock feed. Metadata lint reports 100/100 L2 with zero findings. Notebook Ruff/format and structural checks pass. No engine rebuild, worker change or root dependency modification was required.
