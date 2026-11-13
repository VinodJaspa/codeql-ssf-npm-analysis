#!/usr/bin/env python3
"""
ONE figure for per-query results, replacing the separate malicious and benign per-query plots.

  (a) left : malicious packages detected by each query  (true positives)
  (b) right: benign packages flagged by each query      (false positives)
Both panels share the same query rows, so a reader sees at a glance which queries catch
malware and which ones fire on benign code. The two panels use different x-axes on purpose
(tens of TPs vs. a handful of FPs); each is labelled with its own corpus size.

Input : per_query_tp_fp_summary.csv written by upset_analysis.py
Output: publication_figures/fig_per_query_tp_fp.{pdf,svg,png}
"""
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import MaxNLocator

SUMMARY = Path("../results/upset_analysis/per_query_tp_fp_summary.csv")
OUTPUT_DIR = Path("publication_figures")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Optionally list every query SSF has, so queries that never fired still appear as zero rows
# (a query with no detections and no false positives is not in the findings files).
ALL_QUERIES = None   # e.g. ["pre-post-install-scripts", "os-fingerprinting-exfiltration", ...]

# Used only if the summary file has no unit columns (it has them when UNITS_CSV was found).
N_MALICIOUS_FALLBACK = None
N_BENIGN_FALLBACK = None

COLORS = {"tp": "#009E73", "fp": "#CC79A7", "text": "#222831", "grid": "#DCE1E6"}

mpl.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 9,
    "axes.labelsize": 9.5,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 9,
    "axes.labelcolor": COLORS["text"],
    "text.color": COLORS["text"],
    "xtick.color": COLORS["text"],
    "ytick.color": COLORS["text"],
    "axes.edgecolor": "#AAB2BB",
    "axes.linewidth": 0.7,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.axisbelow": True,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "savefig.bbox": "tight",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "svg.fonttype": "none",
})

df = pd.read_csv(SUMMARY)
need = {"query", "TP_packages", "FP_packages"}
if need - set(df.columns):
    raise ValueError(f"{SUMMARY} is missing columns: {sorted(need - set(df.columns))}")

if ALL_QUERIES:
    extra = [q for q in ALL_QUERIES if q not in set(df["query"])]
    if extra:
        df = pd.concat([df, pd.DataFrame({"query": extra, "TP_packages": 0, "FP_packages": 0})],
                       ignore_index=True)

n_mal = int(df["malicious_units"].iloc[0]) if "malicious_units" in df else N_MALICIOUS_FALLBACK
n_ben = int(df["benign_units"].iloc[0]) if "benign_units" in df else N_BENIGN_FALLBACK
if n_mal is None or n_ben is None:
    print("NOTE: corpus sizes unknown; percentages are omitted from the labels.")

# largest TP at the top
df = df.sort_values(["TP_packages", "FP_packages"], ascending=[True, True]).reset_index(drop=True)
y = range(len(df))

fig, (ax_tp, ax_fp) = plt.subplots(
    1, 2, sharey=True, figsize=(7.4, max(2.8, 0.42 * len(df) + 1.3)),
    gridspec_kw={"width_ratios": [3.0, 1.5], "wspace": 0.06})


def annotate(ax, bars, counts, n):
    for bar, c in zip(bars, counts):
        txt = f"{int(c):,}" if n is None else f"{int(c):,} ({c / n * 100:.1f}%)"
        ax.annotate(txt, xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha="left", va="center", fontsize=8)


b1 = ax_tp.barh(list(y), df["TP_packages"], height=0.62, color=COLORS["tp"],
                edgecolor="white", linewidth=0.6, zorder=3)
b2 = ax_fp.barh(list(y), df["FP_packages"], height=0.62, color=COLORS["fp"],
                edgecolor="white", linewidth=0.6, zorder=3)
annotate(ax_tp, b1, df["TP_packages"], n_mal)
annotate(ax_fp, b2, df["FP_packages"], n_ben)

ax_tp.set_yticks(list(y))
ax_tp.set_yticklabels(df["query"])
ax_tp.tick_params(axis="y", length=0, pad=7)
ax_fp.tick_params(axis="y", length=0)

ax_tp.set_xlim(0, max(1, df["TP_packages"].max()) * 1.38)
ax_fp.set_xlim(0, max(2, df["FP_packages"].max()) * 1.9)
for ax in (ax_tp, ax_fp):
    ax.grid(axis="x", color=COLORS["grid"], linewidth=0.7, zorder=0)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))

ax_tp.set_xlabel("Malicious packages detected" + (f" (N = {n_mal})" if n_mal else ""))
ax_fp.set_xlabel("Benign packages flagged" + (f" (N = {n_ben})" if n_ben else ""))
ax_fp.spines["left"].set_visible(False)

fig.tight_layout()
for ext in ("pdf", "svg", "png"):
    fig.savefig(OUTPUT_DIR / f"fig_per_query_tp_fp.{ext}", **({"dpi": 600} if ext == "png" else {}))
plt.close(fig)

print(df.sort_values("TP_packages", ascending=False).to_string(index=False))
print(f"\nSaved to {OUTPUT_DIR.resolve()}/fig_per_query_tp_fp.(pdf|svg|png)")
print("Percentages are shares of each corpus (all units), not of the 59 detected packages.")