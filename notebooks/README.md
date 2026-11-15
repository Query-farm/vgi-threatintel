# Threat Intelligence notebooks

[An unknown reputation is not a negative verdict](01_triage_reputation_and_unknowns.ipynb)
classifies an authored 12-event stream, checks which supported types are represented,
retrieves six invented verdicts and one unknown result through a loopback feed,
and builds a review queue without replacing missing measurements with zero.

The notebook runs the real **native v0.4.0 worker**. All reputation values are
**synthetic**: `.example` names, a repeated-character hash, private/documentation
addresses and malformed/null controls. No listed indicator is contacted, resolved,
downloaded or scanned. `last_seen` is an authored fixture timestamp, not a real
observation. The score is fixture-only ordering, not a probability, risk estimate,
calibrated vendor scale, detection recall or evidence of safety.

## Run locally or in Colab

Open the notebook's Colab link and Run all. Its short bootstrap installs only the
base shared package and retrieves three immutable, SHA-256-verified companions.
A fresh notebook-only directory works; no worker checkout or source build is used.
Local publication uses the locked runner extra:

```sh
cd notebooks
uv sync --locked
uv run --locked vgi-notebooks 01_triage_reputation_and_unknowns.ipynb
uv run --locked python -m ipykernel install --user --name vgi-threatintel-notebooks --display-name 'VGI Threat Intelligence notebooks'
```

Choose that kernel when opening a local notebook. Python 3.11–3.14 is supported by
this environment; the fresh preloaded-kernel check uses Python 3.12. Dependencies,
companions and the native binary need network access on first use. The analytical
requests go only to an ephemeral `127.0.0.1` HTTP server. Local loopback sockets must
be allowed. A compatible preloaded kernel check is distinct from operating hosted
Colab's UI.

Visible SQL starts the published platform release:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'threatintel' (
 TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-threatintel@v0.4.0'
);
```

The shared connection creates an empty temporary SQL-secret directory with
persistent secrets disabled before ATTACH, and verifies it stays empty. The worker's
supported `base_url` argument explicitly selects the local fixture; no API key is
supplied. Its default endpoint is a placeholder, not a live provider. Real providers
require a separate normalized adapter and their own credentials; this notebook does
not attempt that setup or make a live threat-feed request.

## Change one policy parameter

`MIN_SCORE=70` is an inclusive score cutoff applied only to positive, scored
verdicts. Save the **90** experiment separately:

```sh
uv run --locked vgi-notebooks 01_triage_reputation_and_unknowns.ipynb \
  --parameters '{"MIN_SCORE":90}' --output-dir validation/score-90
```

At 70 the queue has five event rows / four distinct indicators; at 90 it has three
rows / two indicators. Raw verdicts, scores, registry counts, one unknown verdict and
one unscored positive remain unchanged. The two removed candidates reflect a local
rule change, not improved intelligence. Three charts distinguish event counts,
distinct eligible indicators, and the scored subset. Zero-count registry types stay
visible; malformed/null inputs are accounted for separately.

SQL materializes seven explicit literal reputation calls once before captured
display. The worker does not support LATERAL column arguments here. A request audit
requires exactly one GET per distinct eligible indicator: six HTTP 200 and one
HTTP 404. A 404 means no verdict, while other HTTP failures stop execution. The
notebook has 15 SQL checks plus request-count and complete-population assertions.
The runner rejects parameter overrides without a separate destination and protects
the saved default on failure.

## Coverage and validation

[coverage.json](coverage.json) links complete released/current catalog evidence,
visible SQL, successful outputs, interpretations and execution receipts.
The actual release exposes **four logical surfaces**: `indicator_type`,
`is_private_ip`, `reputation`, and the `indicator_types` reference view. All four
have meaningful executed coverage. No tables or COPY formats are hidden from the
inventory. Optional authentication on `reputation` remains in the denominator.

The release tag peels to `b498cf72f83be638afc08e94dd06251b987f2e53`.
Current source `ea201500635a58b771c76c69ffc001865e2602d2` changes examples and comments
only; registration, argument/output schemas, processing and Go dependencies match.
Coverage is **4/4 exact release runtime**, **4/4 current compatible interface** and
**0 current-revision runtime executions**. No current worker was rebuilt.
The proper title/subtitle come from the actual catalog's `vgi.title`/`vgi.subtitle`.

The unchanged worker reuses [green source CI](https://github.com/Query-farm/vgi-threatintel/actions/runs/43584126208).
Notebook validation includes default/experiment execution, an isolated fresh
preloaded-kernel bootstrap, three runner guards, catalog/coverage validation,
figure review and public SVG byte checks. Native-release portability was checked
on macOS ARM64; other platform assets and hosted Colab were not manually operated.

The [shared standard](https://github.com/Query-farm/vgi-example-notebooks/blob/main/docs/standard.md)
defines SVG, branding and execution conventions. Charts are native SVG in Jupyter
and Colab; committed content-addressed SVG image links render them on GitHub.
Generated review PNGs, logs and experiment copies remain ignored. `local_feed.py`
serves the unchanged authored `fixtures/feed.json`; `threatintel_example.py` only
plots SQL-returned data. To upgrade a worker/shared release, recheck catalogs,
fixture semantics, default/experiment results and portable setup before changing pins.
