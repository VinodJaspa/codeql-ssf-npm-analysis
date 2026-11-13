#!/usr/bin/env python3
"""
One script for the RQ1 coverage / failure / cost evidence. It replaces codeql_figures.py,
scale_stats.py and inspect_failures.py.

Unit = one audit entry (one package version we tried to build), no de-duplication.

Outputs (OUT_DIR, default publication_figures/)
  fig1_codeql_execution_time          database-creation and query-evaluation time per built entry
  fig2_codeql_database_outcomes       built vs failed per corpus; failures split by INSPECTED cause
  fig3_failure_source_analysis        install hooks by inspected cause
  fig4_package_size_vs_processing_time  ECDF of query evaluation time per corpus
  codeql_database_outcomes.csv        counts per corpus (entries and packages)
  failure_inspection.csv              one row per failed entry: CodeQL message, inspected class, metrics
  failure_analysis_summary.csv        corpus x CodeQL message x inspected class, with install-hook counts
  codeql_timing_summary.csv           median/IQR/P95/max/total per phase and corpus + Spearman vs size

Inspected classes (heuristics, not proof; report the thresholds and check a sample by hand):
  no_js          no JavaScript/TypeScript file at all
  types_only     only *.d.ts declaration files (the SSF runner hides these before extraction)
  obfuscated     JS/TS present and a strong obfuscation marker fires: >= --hex-idents _0x
                 identifiers, or a long base64 literal together with eval/Function.
  minified       not obfuscated, and >= --min-share of the JS bytes sit in files that look
                 minified: a ".min." file name, a line >= --max-line characters, or a mean
                 line length >= --mean-line characters. Classified per file, so one vendored
                 bundle in an otherwise normal package does not label the whole entry.
  js_other       JS/TS present, no marker fires (the failure is unexplained: look by hand)
  not_inspected  package folder not found under the given root

Escape density (\\xNN/\\uNNNN per KB) is still written to the CSV but no longer decides a class.

Usage
  uv run codeql_analysis.py \
    --audit-malicious ../results/ssf-temporal/ssf_large_scale_npm_io_audit_db.csv \
    --audit-benign    ../results/ssf-temporal/ssf_large_scale_temporal_audit_db.csv\
    --root-malicious  ../temporal_corups \
    --root-benign     ../npm_dataset_io \
    --out-dir publication_figures_temporal
"""
import argparse
import json
import re
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from matplotlib.patches import Patch

BUILT = {"success", "cached"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".es", ".es6", ".ts", ".tsx", ".mts", ".cts"}
DTS_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
HEX_IDENT = re.compile(r"_0x[0-9a-fA-F]{3,}")
ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
B64_LITERAL = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
DYNAMIC = re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(")
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
MAX_READ = 20_000_000

CLASS_STYLE = {   # class -> (label, colour)
    "no_js":         ("No JS/TS file (manifest-only)", "#B2182B"),
    "types_only":    ("Only .d.ts declaration files", "#E69F00"),
    "minified":      ("Minified JS", "#2166AC"),
    "obfuscated":    ("Obfuscated JS", "#7B3294"),
    "syntax_error":  ("Syntax errors or empty JS", "#1B9E77"),
    "js_other":      ("JS present, unexplained", "#9299A3"),
    "not_inspected": ("Package folder not found", "#CBD5E1"),
}
COLORS = {"build": "#142BBF", "query": "#0D9CEF", "success": "#009E73", "text": "#222831",
          "grid": "#DCE1E6", "malicious": "#D55E00", "benign": "#0072B2"}
SYNTAX_MSG = "empty or contained syntax errors"
mpl.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 9, "axes.labelsize": 9.5, "xtick.labelsize": 8.5, "ytick.labelsize": 9,
    "legend.fontsize": 8, "axes.labelcolor": COLORS["text"], "text.color": COLORS["text"],
    "xtick.color": COLORS["text"], "ytick.color": COLORS["text"], "axes.edgecolor": "#AAB2BB",
    "axes.linewidth": 0.7, "axes.spines.top": False, "axes.spines.right": False,
    "axes.axisbelow": True, "axes.unicode_minus": False, "figure.facecolor": "white",
    "axes.facecolor": "white", "savefig.facecolor": "white", "savefig.bbox": "tight",
    "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
})


# =============================================================================
# Inspection
# =============================================================================
def codeql_message(msg):
    m = str(msg).lower()
    if "did not detect any code" in m:
        return "no_code_detected"
    if "detected code written in javascript" in m and "could not process" in m:
        return "extraction_error"
    return "other"


def resolve_root(root, name, version):
    if root is None:
        return None
    for cand in (root / name / "package", root / name / version / "package",
                 root / name / version, root / name):
        if cand.is_dir():
            return cand
    return None


def scan(path, args, full):
    """Sizes for every entry; the (slower) content markers only when full=True."""
    js_files = dts = js_bytes = total_bytes = lines = max_line = 0
    hex_ids = escapes = b64 = dyn = 0
    min_bytes = min_files = 0
    other = {}
    for f in path.rglob("*"):
        if not f.is_file():
            continue
        size = f.stat().st_size
        total_bytes += size
        name = f.name.lower()
        if name.endswith(DTS_SUFFIXES):
            dts += 1
            continue
        ext = f.suffix.lower()
        if ext not in JS_EXT:
            other[ext or f.name] = other.get(ext or f.name, 0) + 1
            continue
        js_files += 1
        js_bytes += size
        if full:
            text = f.read_bytes()[:MAX_READ].decode("utf-8", errors="ignore")
            ls = text.split("\n")
            lines += len(ls)
            fmax = max((len(x) for x in ls), default=0)
            max_line = max(max_line, fmax)
            # per-file minification test
            if (fmax >= args.max_line
                    or len(text) / max(len(ls), 1) >= args.mean_line
                    or ".min." in name):
                min_bytes += size
                min_files += 1
            hex_ids += len(HEX_IDENT.findall(text))
            escapes += len(ESCAPES.findall(text))
            b64 += len(B64_LITERAL.findall(text))
            dyn += len(DYNAMIC.findall(text))

    out = {"js_files": js_files, "dts_files": dts, "js_kb": js_bytes / 1024,
           "total_kb": total_bytes / 1024}
    if not full:
        return out

    scripts = {}
    pj = path / "package.json"
    if pj.exists():
        try:
            scripts = json.loads(pj.read_text(errors="ignore")).get("scripts", {}) or {}
        except Exception:
            scripts = {}
    hooks = [h for h in INSTALL_HOOKS if h in scripts]

    min_share = min_bytes / js_bytes if js_bytes else 0.0
    esc_per_kb = escapes / (js_bytes / 1024) if js_bytes else 0.0
    obf = hex_ids >= args.hex_idents or (b64 >= 1 and dyn >= 1)
    if js_files == 0:
        cls = "types_only" if dts else "no_js"
    elif obf:
        cls = "obfuscated"
    elif min_share >= args.min_share:
        cls = "minified"
    else:
        cls = "js_other"
    markers = "+".join(m for m, on in (("hex_identifiers", hex_ids >= args.hex_idents),
                                       ("base64_eval", b64 >= 1 and dyn >= 1),
                                       ("minified_files", min_share >= args.min_share)) if on)

    out.update({"class": cls, "markers": markers, "max_line_len": max_line,
                "mean_line_len": round(js_bytes / lines, 1) if lines else 0.0,
                "min_share": round(min_share, 3), "min_files": min_files,
                "hex_identifiers": hex_ids, "escapes_per_kb": round(esc_per_kb, 2),
                "base64_literals": b64, "dynamic_exec_calls": dyn,
                "install_hooks": ",".join(hooks),
                "other_files": json.dumps(dict(sorted(other.items(), key=lambda kv: -kv[1])[:5]))})
    return out


# =============================================================================
# Loading
# =============================================================================
def load(args):
    frames = []
    for label, audit, root in (("malicious", args.audit_malicious, args.root_malicious),
                               ("benign", args.audit_benign, args.root_benign)):
        df = pd.read_csv(audit, dtype=str, keep_default_na=False)
        for c in ("package", "version", "database_status"):
            if c not in df:
                raise SystemExit(f"{audit} is missing column '{c}'")
        for c in ("error_message", "queries_processed"):
            if c not in df:
                df[c] = ""
        for c in ("build_time_seconds", "query_time_seconds", "package_time_seconds"):
            df[c] = pd.to_numeric(df[c], errors="coerce") if c in df else np.nan
        df["corpus"] = label
        df["built"] = df["database_status"].str.strip().str.lower().isin(BUILT)
        df["codeql_message"] = np.where(df["built"], "built", df["error_message"].map(codeql_message))
        df["_root"] = [resolve_root(Path(root) if root else None, p, v)
                       for p, v in zip(df["package"], df["version"])]
        frames.append(df)
    d = pd.concat(frames, ignore_index=True)

    rows = []
    n_missing = 0
    for _, r in d.iterrows():
        if r["_root"] is None:
            n_missing += 1
            rows.append({"class": "not_inspected" if not r["built"] else ""})
            continue
        rows.append(scan(r["_root"], args, full=not r["built"]))
    ins = pd.DataFrame(rows)
    d = pd.concat([d.drop(columns=["_root"]), ins], axis=1)

    # reclassify: CodeQL says the JS it found was empty or had syntax errors
    syn = ((~d["built"]) & d["class"].eq("js_other")
           & d["error_message"].str.lower().str.contains(SYNTAX_MSG, regex=False))
    d.loc[syn, "class"] = "syntax_error"
    print(f"Reclassified {int(syn.sum())} failed entries as syntax_error.")

    if n_missing:
        print(f"WARNING: {n_missing} audit entries have no package folder under the given roots "
              "(sizes missing; failed ones are classed not_inspected)")

    # package-level: did ANY version of the package build?
    any_built = d.groupby(["corpus", "package"])["built"].transform("any")
    d["package_never_built"] = ~any_built
    d["avg_time_per_query_seconds"] = d["query_time_seconds"] / pd.to_numeric(
        d["queries_processed"], errors="coerce").where(lambda s: s > 0)
    if d["package_time_seconds"].isna().all():
        d["package_time_seconds"] = d["build_time_seconds"].fillna(0) + d["query_time_seconds"].fillna(0)
    return d


def save(fig, out, stem):
    for ext in ("pdf", "svg"):
        fig.savefig(out / f"{stem}.{ext}")
    plt.close(fig)


# =============================================================================
# Tables
# =============================================================================
def stats(s):
    s = pd.to_numeric(s, errors="coerce").dropna()
    if s.empty:
        return {"n": 0}
    return {"n": len(s), "median": s.median(), "q1": s.quantile(.25), "q3": s.quantile(.75),
            "p95": s.quantile(.95), "max": s.max(), "total": s.sum()}


def tables(d, out):
    classes = list(CLASS_STYLE)
    rows = []
    for name, g in [("malicious", d[d.corpus == "malicious"]), ("benign", d[d.corpus == "benign"]), ("all", d)]:
        f = g[~g.built]
        rec = {"corpus": name, "entries": len(g), "built": int(g.built.sum()), "failed": len(f),
               "built_pct": 100 * g.built.mean(),
               "packages": g.drop_duplicates(["corpus", "package"]).shape[0],
               "packages_never_built": g[g.package_never_built].drop_duplicates(["corpus", "package"]).shape[0]}
        for m in ("no_code_detected", "extraction_error", "other"):
            rec[f"codeql_{m}"] = int((f.codeql_message == m).sum())
        for c in classes:
            rec[f"inspected_{c}"] = int((f["class"] == c).sum())
        rows.append(rec)
    outcomes = pd.DataFrame(rows)
    outcomes.to_csv(out / "codeql_database_outcomes.csv", index=False)

    failed = d[~d.built].copy()
    keep = ["corpus", "package", "version", "codeql_message", "class", "markers", "js_files", "dts_files",
            "js_kb", "total_kb", "max_line_len", "mean_line_len", "min_share", "min_files",
            "hex_identifiers", "escapes_per_kb", "base64_literals", "dynamic_exec_calls",
            "install_hooks", "other_files", "package_never_built", "package_time_seconds"]
    failed[[c for c in keep if c in failed]].to_csv(out / "failure_inspection.csv", index=False)
    if not failed.empty:

        if "install_hooks" in failed.columns:
            failed["has_hook"] = failed["install_hooks"].fillna("").ne("")
        else:
            failed["has_hook"] = False

        if "package_never_built" not in failed.columns:
            failed["package_never_built"] = False

        summ = (
            failed.groupby(["corpus", "codeql_message", "class"])
            .agg(
                entries=("package", "size"),
                with_install_hook=("has_hook", "sum"),
                without_install_hook=("has_hook", lambda x: (~x).sum()),
                packages_never_built=("package_never_built", "sum")
            )
            .reset_index()
        )

        summ.to_csv(out / "failure_analysis_summary.csv", index=False)


    trows = []
    metrics = ["build_time_seconds", "query_time_seconds", "package_time_seconds",
               "avg_time_per_query_seconds"]
    for name, g in [("malicious", d[d.corpus == "malicious"]), ("benign", d[d.corpus == "benign"]), ("all", d)]:
        b = g[g.built]
        for m in metrics:
            rec = {"corpus": name, "metric": m.replace("_seconds", ""), **stats(b[m])}
            ok = b[[m, "js_kb"]].apply(pd.to_numeric, errors="coerce").dropna()
            ok = ok[(ok["js_kb"] > 0)]
            if len(ok) >= 10:
                rho, p = spearmanr(ok["js_kb"], ok[m])
                rec["spearman_rho_vs_js_kb"], rec["spearman_p"] = rho, p
            trows.append(rec)
        trows.append({"corpus": name, "metric": "time_spent_on_failed_entries",
                      **stats(g[~g.built]["package_time_seconds"])})
    timing = pd.DataFrame(trows)
    timing.to_csv(out / "codeql_timing_summary.csv", index=False)
    return outcomes, summ, timing


# =============================================================================
# Figures
# =============================================================================
def fmt_s(x):
    return f"{x:.1f}s" if x < 100 else f"{x:.0f}s"


def fig1(d, out):
    b = d[d.built]
    data = []
    for col, label, color in (("build_time_seconds", "Database creation", COLORS["build"]),
                              ("query_time_seconds", "Query evaluation", COLORS["query"])):
        v = pd.to_numeric(b[col], errors="coerce").to_numpy()
        v = v[np.isfinite(v) & (v > 0)]
        print(f"label={label}, n={len(v)} built entries with positive {col} values.")

        if len(v) > 0:
            data.append((label, color, v))
        else:
            print(f"[NOTICE] Skipping '{label}' in Fig. 1: No positive timing values found (entries are cached or 0s).")

    if not data:
        print("Fig. 1 skipped: no positive finite times available for plotting.")
        return

    fig, ax = plt.subplots(figsize=(6.2, 2.6))
    pos = np.arange(len(data))[::-1]

    for p, (label, c, v) in zip(pos, data):
        ax.boxplot(v, positions=[p], vert=False, widths=0.38, whis=1.5, showfliers=False,
                   patch_artist=True, manage_ticks=False,
                   boxprops={"facecolor": c, "edgecolor": c, "alpha": 0.20, "linewidth": 1.1},
                   medianprops={"color": c, "linewidth": 1.8},
                   whiskerprops={"color": c, "linewidth": 1.0}, capprops={"color": c, "linewidth": 1.0})

        rng = np.random.default_rng(42)
        sample = v if len(v) <= 500 else rng.choice(v, size=500, replace=False)
        ax.scatter(sample, p + rng.uniform(-0.09, 0.09, size=len(sample)), s=6, color=c,
                   alpha=0.18, edgecolors="none", rasterized=True, zorder=2)

        median_val = np.median(v)
        ax.annotate(f"Median: {fmt_s(median_val)}", xy=(median_val, p), xytext=(8, 12),
                    textcoords="offset points", fontsize=8, color=c, fontweight="bold",
                    bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.8))

    ax.set_yticks(pos)
    ax.set_yticklabels([x[0] for x in data], fontweight="semibold")
    ax.set_xscale("log")
    ax.set_xlabel("Processing Time per Entry (seconds, log scale)")
    ax.grid(axis="x", which="major", color=COLORS["grid"], linewidth=0.7)
    ax.grid(axis="x", which="minor", color=COLORS["grid"], linewidth=0.35, linestyle=":", alpha=0.5)
    ax.tick_params(axis="y", length=0, pad=6)
    ax.set_ylim(-0.6, len(data) - 0.4)
    ax.margins(x=0.12)
    fig.tight_layout()
    save(fig, out, "fig1_codeql_execution_time")
    print(f"Fig. 1 saved: n={len(b)} built entries.")


def fig2(d, out):
    FAIL = "#4A4F57"   # neutral failure colour
    fig, ax = plt.subplots(figsize=(6.5, 2.2))
    corpora = ("benign", "malicious")
    ypos = np.arange(len(corpora))[::-1]

    for y, corpus in zip(ypos, corpora):
        g = d[d.corpus == corpus]
        n = len(g)
        n_ok = int(g.built.sum())
        n_fail = n - n_ok
        ok_pct = 100 * n_ok / n
        fail_pct = 100 - ok_pct

        ax.barh(y, ok_pct, height=0.5, color=COLORS["success"], zorder=3)
        ax.barh(y, fail_pct, left=ok_pct, height=0.5, color=FAIL, zorder=3)

        ax.text(ok_pct / 2, y, f"{n_ok:,} ({ok_pct:.1f}%)", ha="center", va="center",
                color="white", fontsize=8, fontweight="bold")
        ax.annotate(f"{n_fail:,} ({fail_pct:.1f}%)", xy=(100, y), xytext=(6, 0),
                    textcoords="offset points", va="center", fontsize=8, fontweight="semibold")

    ax.set_yticks(ypos)
    ax.set_yticklabels([f"{c.capitalize()}\n(n={(d.corpus == c).sum():,})" for c in corpora],
                       fontsize=8.5)
    ax.set_xlim(0, 118)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("Share of Audit Entries (%)")
    ax.grid(axis="x", color=COLORS["grid"], linewidth=0.6, zorder=0)
    ax.tick_params(axis="y", length=0, pad=6)
    ax.spines["left"].set_visible(False)
    ax.legend([Patch(color=COLORS["success"]), Patch(color=FAIL)],
              ["Database built (success + cached)", "Database creation failed"],
              loc="upper center", bbox_to_anchor=(0.5, -0.3), ncol=2,
              frameon=False, fontsize=7.5)

    fig.tight_layout(pad=0.8)
    save(fig, out, "fig2_codeql_database_outcomes")
    print("Fig. 2 saved.")


def fig3(d, out):
    f = d[~d.built].copy()
    if f.empty:
        print("Fig. 3 skipped: no failed entries")
        return
    if f["install_hooks"].isna().all():
        print("Fig. 3 skipped: no install hook information available")
        return
    f["has_hook"] = f["install_hooks"].fillna("").ne("")
    classes = [c for c in CLASS_STYLE if (f["class"] == c).any()]

    fig, ax = plt.subplots(figsize=(6.8, 3.9))
    ypos = np.arange(len(classes))[::-1]
    offs = {"malicious": 0.2, "benign": -0.2}

    for y, c in zip(ypos, classes):
        for corpus, off in offs.items():
            g = f[(f["class"] == c) & (f.corpus == corpus)]
            yes, no = int(g.has_hook.sum()), int((~g.has_hook).sum())
            if yes + no == 0:
                continue
            col = COLORS[corpus]
            ax.barh(y + off, yes, height=0.34, color=col, zorder=3)
            ax.barh(y + off, no, left=yes, height=0.34, color=col, alpha=0.30, zorder=3)
            ax.text(yes + no + 0.25, y + off, f"{yes}/{yes + no}",
                    va="center", fontsize=8, fontweight="semibold")

    ax.set_yticks(ypos)
    ax.set_yticklabels([CLASS_STYLE[c][0].split(" (")[0] for c in classes], fontsize=8.5)
    ax.set_xlabel("Number of Failed Entries (hook / total)")
    mx = int(f.groupby(["class", "corpus"]).size().max())
    ax.set_xlim(0, max(12, int(mx * 1.3)))
    ax.xaxis.set_major_locator(mpl.ticker.MaxNLocator(integer=True))
    ax.grid(axis="x", color=COLORS["grid"], linewidth=0.6, zorder=0)
    ax.tick_params(axis="y", length=0, pad=6)
    ax.spines["left"].set_visible(False)

    nm = int((f.corpus == "malicious").sum())
    nb = int((f.corpus == "benign").sum())
    ax.legend(
        [Patch(color=COLORS["malicious"]), Patch(color=COLORS["benign"]),
         Patch(color="#555555"), Patch(color="#555555", alpha=0.30)],
        [f"Malicious (n={nm})", f"Benign (n={nb})",
         "Has install hook (solid)", "No install hook (faded)"],
        loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2,
        frameon=False, fontsize=7.5)

    fig.tight_layout()
    save(fig, out, "fig3_failure_source_analysis")
    print("Fig. 3 saved.")


def fig4(d, out):
    # Empirical CDF of query evaluation cost per corpus
    fig, ax = plt.subplots(figsize=(6.0, 3.2))

    for corpus in ("benign", "malicious"):
        vals = pd.to_numeric(d[(d.corpus == corpus) & d.built]['query_time_seconds'], errors='coerce').dropna()
        vals = vals[vals > 0].sort_values()
        if len(vals) > 0:
            y = np.arange(1, len(vals) + 1) / len(vals)
            ax.plot(vals, y, label=f"{corpus.capitalize()} (n={len(vals)})", color=COLORS[corpus], linewidth=2.0)

    ax.set_xscale("log")
    ax.set_xlabel("Query Evaluation Time (seconds, log scale)")
    ax.set_ylabel("Empirical CDF $P(X \\leq x)$")
    ax.grid(color=COLORS["grid"], linewidth=0.5, zorder=0)
    ax.legend(frameon=False, loc="lower right")

    fig.tight_layout()
    save(fig, out, "fig4_package_size_vs_processing_time")
    print("Fig. 4 generated successfully as ECDF plot.")


# =============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-malicious", required=True)
    ap.add_argument("--audit-benign", required=True)
    ap.add_argument("--root-malicious", help="folder holding the malicious package folders")
    ap.add_argument("--root-benign", help="folder holding the benign package folders")
    ap.add_argument("--out-dir", default="publication_figures")
    ap.add_argument("--hex-idents", type=int, default=20)
    ap.add_argument("--max-line", type=int, default=5000)
    ap.add_argument("--mean-line", type=float, default=200,
                    help="mean characters per line above which a file counts as minified")
    ap.add_argument("--min-share", type=float, default=0.5,
                    help="share of JS bytes in minified files above which the entry is 'minified'")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    d = load(args)
    outcomes, summ, timing = tables(d, out)
    fig1(d, out)
    fig2(d, out)
    fig3(d, out)
    fig4(d, out)

    pd.set_option("display.width", 220)
    print("\nOUTCOMES")
    print(outcomes.round(2).to_string(index=False))
    print("\nFAILURES: corpus x CodeQL message x inspected class")
    print(summ.to_string(index=False))
    print("\nTIMING (built entries, seconds)")
    print(timing.round(3).to_string(index=False))
    tot = timing[(timing.corpus == "all") & (timing.metric == "package_time")]
    if not tot.empty and tot["n"].iloc[0]:
        t = tot.iloc[0]
        print(f"\nSequential time for {int(t['n'])} built entries: {t['total'] / 3600:.2f} h "
              f"(median {t['median']:.0f} s, P95 {t['p95']:.0f} s per entry; parallelism not accounted for)")
    print(f"\nwrote figures and tables to {out.resolve()}")


if __name__ == "__main__":
    main()