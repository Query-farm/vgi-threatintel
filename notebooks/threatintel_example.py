"""Presentation only; SQL owns classification, counting, joins and queue policy."""

import matplotlib.pyplot as plt
import numpy as np
from vgi_notebooks import finish

COLORS = {
    "review candidate": "#b25b3f",
    "positive, below threshold": "#b48c49",
    "positive, unscored": "#71568b",
    "negative verdict": "#397d62",
    "no verdict": "#397f91",
    "private/reserved IP": "#69757f",
    "unrecognized": "#9b9f9e",
    "missing input": "#c1c8c4",
}
SOURCE = (
    "Source: authored 12-event stream + invented normalized feed; no real threat verdicts\n"
    "VGI Threat Intelligence v0.4.0 native release + visible SQL · loopback fixture only"
)


def type_population(data):
    fig, ax = plt.subplots(figsize=(11.8, 6.4))
    y = np.arange(len(data))
    ax.barh(y - 0.17, data.event_rows, height=0.3, color="#397f91", label="Event rows (duplicates retained)")
    ax.barh(y + 0.17, data.eligible_indicators, height=0.3, color="#b48c49", label="Distinct eligible indicators")
    for i, row in enumerate(data.itertuples()):
        ax.text(row.event_rows + 0.09, i - 0.17, str(int(row.event_rows)), va="center", fontsize=10)
        ax.text(row.eligible_indicators + 0.09, i + 0.17, str(int(row.eligible_indicators)), va="center", fontsize=10)
    ax.set_yticks(y, data.indicator_type)
    ax.invert_yaxis()
    ax.set(xlabel="Count · different units shown separately", xlim=(0, data.event_rows.max() + 1.2))
    ax.set_xticks(range(int(data.event_rows.max()) + 2))
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "Supported types are not the same as represented types",
        "Seven registry types · zero counts retained · untyped inputs remain in the event table",
        SOURCE,
        name="01-type-population",
    )


def queue_accounting(counts, total, threshold):
    order = counts.sort_values(["event_rows", "queue_status"])
    fig, ax = plt.subplots(figsize=(11.8, 6.5))
    ax.barh(order.queue_status, order.event_rows, color=[COLORS[s] for s in order.queue_status], height=0.62)
    for i, row in enumerate(order.itertuples()):
        ax.text(row.event_rows + 0.08, i, str(int(row.event_rows)), va="center")
    ax.set(
        xlabel="Original event rows · count (duplicates retained)",
        ylabel="",
        xlim=(0, max(6, order.event_rows.max() + 1)),
    )
    ax.set_xticks(range(0, max(6, int(order.event_rows.max()) + 1) + 1))
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "Every input keeps a reason for its queue status",
        f"{total} event rows · inclusive score threshold {threshold} · absent verdicts and scores stay null",
        SOURCE,
        name="02-queue-accounting",
    )


def scored_subset(scored, threshold):
    fig, ax = plt.subplots(figsize=(12, 6))
    labels = ["sha256: " + s[:8] + "…" if len(s) == 64 else s.replace("https://", "") for s in scored.indicator]
    ax.barh(labels, scored.score, color=[COLORS[s] for s in scored.queue_status], height=0.55)
    for i, row in enumerate(scored.itertuples()):
        ax.text(
            row.score + 1.3,
            i,
            f"{row.score:g} · {'positive' if row.malicious else 'negative'}",
            va="center",
            fontsize=10,
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.5},
            zorder=5,
        )
    ax.axvline(threshold, color="#243e32", linestyle="--", label=f"Inclusive queue threshold: {threshold}")
    ax.set(xlabel="Invented feed score · points on this fixture’s 0–100 scale", ylabel="", xlim=(0, 130))
    ax.set_xticks(range(0, 101, 20))
    ax.grid(axis="y", visible=False)
    ax.legend(loc="upper left", bbox_to_anchor=(0, 1.17), fontsize=10)
    finish(
        fig,
        "Scores support a rule; they do not replace verdicts",
        "Distinct scored indicators only · missing scores omitted, never plotted as zero",
        SOURCE,
        name="03-scored-subset",
    )
