#!/usr/bin/env python3
"""
Per-query and query-combination analysis of SSF detections, for BOTH labels:
  malicious -> true positives   (which queries catch the malware)
  benign    -> false positives  (which queries fire on benign packages)

Outputs, under OUTPUT_DIR:
  malicious/  and  benign/   each with
      package_query_presence_matrix.csv
      per_query_package_counts.csv
      exact_query_combination_counts.csv
      package_detection_degree_distribution.csv
      fig1_per_query_distribution.{pdf,png}
      fig2_combined_query_upset.{pdf,png}      (only if >= 2 queries fired)
  per_query_tp_fp_summary.csv                  one row per query: TP, FP, recall share, FPR

If UNITS_CSV exists (written by calculate_confusion_matrix.py), the analysis is
restricted to exactly the packages the confusion matrix counted as SSF detections,
and the per-query rates use the evaluation's unit counts as denominators. Without it,
the findings files are used as they are and rates are skipped.
NOTE: if the confusion matrix was run with --ignore-paths or --queries, the units file
already reflects that, but the findings read here do not; apply the same filter or the
figures and the table will describe different detections.
"""
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd
from upsetplot import UpSet

# =============================================================================
# Configuration
# =============================================================================
FINDINGS = {
    "malicious": Path("../results/validation-set-codeql/ssf_validation-set-malicious.csv"),
    "benign": Path("../results/validation-set-codeql/ssf_validation-set-benign.csv"),
}
OUTPUT_DIR = Path("../results/upset_analysis")

# Units file from calculate_confusion_matrix.py (use the population you report, usually "all").
UNITS_CSV = Path("../results/confusion_units.csv")

COLORS = {
    "malicious": "#009E73",   # green
    "benign": "#CC79A7",      # pink
    "grid": "#E2E8F0",
    "text": "#1E293B",
    "background": "#F8FAFC",
    "neutral": "#CBD5E1",
}

mpl.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 9,
    "axes.titlesize": 11,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "axes.edgecolor": "#AAB2BB",
    "axes.linewidth": 0.7,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.axisbelow": True,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


# =============================================================================
# Helpers
# =============================================================================
def load_units():
    """Return (restrict, n_units): per-label sets of SSF-detected packages and unit counts."""
    if not UNITS_CSV.exists():
        print(f"NOTE: {UNITS_CSV} not found; no restriction to confusion-matrix units, "
              "and per-query rates will be skipped.")
        return None, None
    u = pd.read_csv(UNITS_CSV, dtype=str, keep_default_na=False)
    u["label"] = u["label"].str.strip().str.lower()
    restrict = {lab: set(u.loc[(u["label"] == lab) & (u["ssf_det"] == "1"), "package"])
                for lab in FINDINGS}
    n_units = {lab: int((u["label"] == lab).sum()) for lab in FINDINGS}
    print(f"Units file: {n_units} units; SSF-detected: { {k: len(v) for k, v in restrict.items()} }")
    return restrict, n_units


def load_findings(label, csv, restrict):
    df = pd.read_csv(csv)
    missing = {"package", "label", "query"} - set(df.columns)
    if missing:
        raise ValueError(f"{csv} is missing columns: {sorted(missing)}")
    for c in ("package", "query", "label"):
        df[c] = df[c].astype("string").str.strip()
    df["label"] = df["label"].str.lower()
    df = df.dropna(subset=["package", "query"])
    df = df[df["package"].ne("") & df["query"].ne("") & df["label"].eq(label)].copy()

    print(f"\n[{label}] finding rows: {len(df):,}; packages: {df['package'].nunique():,}; "
          f"queries: {df['query'].nunique():,}")

    if restrict is not None:
        keep = restrict[label]
        extra = set(df["package"]) - keep
        absent = keep - set(df["package"])
        if extra:
            print(f"[{label}] dropping {len(extra)} package(s) in the findings file that the "
                  f"confusion matrix did not count as detections (e.g. other versions): "
                  f"{sorted(extra)[:5]}")
        if absent:
            print(f"WARNING [{label}]: {len(absent)} confusion-matrix detection(s) have no "
                  f"finding rows here (query/path filter mismatch?): {sorted(absent)[:5]}")
        df = df[df["package"].isin(keep)].copy()
    return df


def analyze(label, df, out_dir):
    """Write tables and figures for one label; return the package x query boolean matrix."""
    out_dir.mkdir(parents=True, exist_ok=True)
    color = COLORS[label]
    what = "true positives" if label == "malicious" else "false positives"

    if df.empty:
        print(f"[{label}] no findings after filtering; nothing to plot.")
        return pd.DataFrame()

    pairs = df[["package", "query"]].drop_duplicates()   # one package-query pair = one detection
    matrix = pd.crosstab(pairs["package"], pairs["query"]).gt(0).astype(bool)
    matrix = matrix.reindex(sorted(matrix.columns), axis=1)
    n = matrix.shape[0]
    print(f"[{label}] detected packages ({what}): {n}")
    matrix.astype(int).to_csv(out_dir / "package_query_presence_matrix.csv")

    # ---- exact combinations (computed before plotting so the UpSet can be verified)
    combo = matrix.apply(lambda r: " + ".join(r.index[r.to_numpy()]), axis=1)
    cc = (combo.value_counts().rename_axis("query_combination")
          .rename("unique_packages").reset_index())
    cc["percentage_of_detected_packages"] = cc["unique_packages"] / n * 100
    cc.to_csv(out_dir / "exact_query_combination_counts.csv", index=False)
    assert cc["unique_packages"].sum() == n, "combination counts do not sum to N"

    degree = (matrix.sum(axis=1).value_counts().sort_index()
              .rename_axis("number_of_queries").rename("unique_packages").reset_index())
    degree["percentage_of_detected_packages"] = degree["unique_packages"] / n * 100
    degree.to_csv(out_dir / "package_detection_degree_distribution.csv", index=False)

    # ---- UpSet
    active = matrix.loc[:, matrix.any(axis=0)].astype(bool)
    if active.shape[1] < 2:
        print(f"[{label}] only {active.shape[1]} query fired; UpSet skipped "
              "(use per_query_package_counts.csv or a table instead).")
    else:
        idx = pd.MultiIndex.from_frame(active.reset_index(drop=True),
                                       names=active.columns.tolist())
        data = pd.Series(1, index=idx, name="package_count")
        fig = plt.figure(figsize=(10, 6.5))
        # No max_subset_size: it removes every intersection LARGER than the value.
        upset = UpSet(data, subset_size="sum", sort_by="cardinality",
                      sort_categories_by="cardinality", show_counts=True,
                      min_subset_size=1, facecolor=color,
                      other_dots_color=COLORS["neutral"],
                      shading_color=COLORS["background"], with_lines=True)
        if hasattr(upset, "intersections"):
            shown = int(upset.intersections.sum())
            assert shown == n, f"[{label}] UpSet shows {shown} of {n} packages"
            print(f"[{label}] UpSet check OK: {shown} of {n} packages shown.")
        else:
            print(f"[{label}] NOTE: no .intersections in this upsetplot version; "
                  "compare bar sum with exact_query_combination_counts.csv.")
        upset.plot(fig=fig)
        fig.savefig(out_dir / "fig2_combined_query_upset.pdf", bbox_inches="tight")
        fig.savefig(out_dir / "fig2_combined_query_upset.png", dpi=600, bbox_inches="tight")
        plt.close(fig)

    print(f"[{label}] packages by number of queries that fired:")
    print(degree.to_string(index=False))
    print(f"[{label}] most frequent exact combinations:")
    print(cc.head(10).to_string(index=False))
    return matrix


def summary_table(matrices, n_units):
    """One row per query: packages detected in each label and the corresponding rates."""
    queries = sorted(set().union(*[set(m.columns) for m in matrices.values() if not m.empty]))
    rows = []
    for q in queries:
        tp = int(matrices["malicious"][q].sum()) if q in matrices["malicious"].columns else 0
        fp = int(matrices["benign"][q].sum()) if q in matrices["benign"].columns else 0
        row = {"query": q, "TP_packages": tp, "FP_packages": fp}
        if n_units:
            row["malicious_units"] = n_units["malicious"]
            row["benign_units"] = n_units["benign"]
            row["recall_share"] = tp / n_units["malicious"]
            row["FPR"] = fp / n_units["benign"]
        rows.append(row)
    return pd.DataFrame(rows).sort_values("TP_packages", ascending=False)


# =============================================================================
# Main
# =============================================================================
def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    restrict, n_units = load_units()

    matrices = {}
    for label, csv in FINDINGS.items():
        df = load_findings(label, csv, restrict)
        matrices[label] = analyze(label, df, OUTPUT_DIR / label)

    if all(not m.empty for m in matrices.values()) or any(not m.empty for m in matrices.values()):
        for lab in matrices:
            if matrices[lab].empty:
                matrices[lab] = pd.DataFrame(columns=[])
        table = summary_table(matrices, n_units)
        table.to_csv(OUTPUT_DIR / "per_query_tp_fp_summary.csv", index=False)
        print("\nPER-QUERY TP / FP SUMMARY")
        pd.set_option("display.width", 200)
        print(table.round(4).to_string(index=False))

    print(f"\nAll outputs saved to: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()