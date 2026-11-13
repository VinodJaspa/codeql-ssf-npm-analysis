#!/usr/bin/env python3
"""
Confusion matrices for SSF (CodeQL) and GuardDog on the SAME units.

Why two kinds of input per tool: a findings CSV lists only units that produced a finding.
Zero-finding units (every true negative and every missed malware) exist only in the
audit/summary CSV, so the denominator must come from there.

Inputs accept an optional corpus tag:  path::tag   (the tag defaults to the file name).
Use the SAME tag for the audit, summary AND findings files of one corpus. Findings are
joined on (corpus, package, version, label), so a mismatched tag means zero detections;
the script warns when findings cannot be matched to any audited unit.

Placeholder versions ("package", "unknown", "", anything that is not valid semver) are
normalised to "unknown", so SSF and GuardDog rows for the same package line up.

Example (no whitespace after any backslash):
uv run confusion_matrix.py \
  --ssf-audit ../results/validation-set-codeql/ssf_validation-set_audit_db_benign.csv::benign \
              ../results/validation-set-codeql/ssf_validation-set_audit_db.csv::mal \
  --ssf-findings ../results/validation-set-codeql/ssf_validation-set-benign.csv::benign \
                 ../results/validation-set-codeql/ssf_validation-set-malicious.csv::mal \
  --gd-summary ../results/guarddog-validation/guarddog_summary_validation-set-benign.csv::benign \
               ../results/guarddog-validation/guarddog_summary_validation-set.csv::mal \
  --gd-findings ../results/guarddog-validation/guarddog_findings_validation-set-benign.csv::benign \
                ../results/guarddog-validation/guarddog_findings_validation-set.csv::mal \
   --population all \
     --unit version \
   --out-prefix validation_all
 
    # Temporal
      uv run confusion_matrix.py \
  --ssf-audit ../results/ssf-temporal/ssf_large_scale_npm_io_audit_db.csv::benign \
              ../results/ssf-temporal/ssf_large_scale_temporal_audit_db.csv::mal \
  --ssf-findings ../results/ssf-temporal/ssf_large_scale_npm_io.csv::benign \
                 ../results/ssf-temporal/ssf_large_scale_temporal.csv::mal \
--gd-summary ../results/guarddog-temporal/guarddog_large_summary_npm_io.csv::benign \
                 ../results/guarddog-temporal/guarddog_large_summary_temporal.csv::mal \
    --gd-findings ../results/guarddog-temporal/guarddog_large_summary_npm_io.csv::benign \
                  ../results/guarddog-temporal/guarddog_large_findings_temporal.csv::mal \
   --population common --out-prefix temporal_comman
"""
# //Check for all and comand-line args: uv run confusion_matrix_validation.py --help
# uv run calculate_confusion_matrix.py <same args> --population all --out-prefix cm_all
# uv run calculate_confusion_matrix.py <same args> --population common --out-prefix cm_common
import argparse
import math
import sys
from pathlib import Path

import pandas as pd
from packaging.version import InvalidVersion, Version
import semantic_version
from scipy.stats import binomtest

KEY = ["corpus", "package", "version", "label"]
TRUE_STRINGS = {"true": 1, "yes": 1, "1": 1, "false": 0, "no": 0, "0": 0, "": 0}


def warn(msg):
    print(f"WARNING: {msg}", file=sys.stderr)


def split(items):
    out = []
    for it in items or []:
        path, _, tag = it.partition("::")
        out.append((path, tag or Path(path).stem))
    return out


def norm_version(v):
    v = str(v).strip()
    try:
        return str(semantic_version.Version(v))
    except ValueError:
        return "unknown"


def read(path, cols):
    df = pd.read_csv(path, dtype=str, keep_default_na=False, usecols=cols)
    if "label" in df:
        df["label"] = df["label"].str.strip().str.lower()
    if "version" in df:
        df["version"] = df["version"].map(norm_version)
    return df


def collapse_rows(df):
    return df.groupby(KEY, as_index=False).max()


def drop_ignored(f, ignore):
    """Drop findings whose file matches the regex. Findings with NO file path
    (e.g. GuardDog metadata heuristics) are kept: a path filter cannot apply to them."""
    if not ignore:
        return f
    hit = f["file"].ne("") & f["file"].str.contains(ignore, regex=True)
    return f[~hit]


# ----------------------------------------------------------------- loaders
def load_ssf(audits, findings, queries, ignore):
    u = pd.concat([read(p, ["package", "version", "label", "database_status"]).assign(corpus=t)
                   for p, t in audits], ignore_index=True)
    u["ssf_ok"] = u["database_status"].isin(["success", "cached"]).astype(int)

    f = pd.concat([read(p, ["package", "version", "label", "query", "file"]).assign(corpus=t)
                   for p, t in findings], ignore_index=True)
    all_q = sorted(set(f["query"]))
    if queries:
        f = f[f["query"].isin(queries)]
    f = drop_ignored(f, ignore)

    hit = f[KEY].drop_duplicates().assign(ssf_det=1)
    orphans = hit.merge(u[KEY].drop_duplicates(), on=KEY, how="left", indicator=True)
    n_orphan = int((orphans["_merge"] == "left_only").sum())
    if n_orphan:
        warn(f"{n_orphan} SSF finding unit(s) match no audited unit (tag/package/label mismatch?)")

    u = u.merge(hit, on=KEY, how="left")
    u["ssf_det"] = u["ssf_det"].fillna(0).astype(int)
    return collapse_rows(u[KEY + ["ssf_ok", "ssf_det"]]), all_q


def load_gd(summaries, findings, ignore):
    u = pd.concat([read(p, ["package", "version", "label", "status", "detected"]).assign(corpus=t)
                   for p, t in summaries], ignore_index=True)
    u["gd_ok"] = (u["status"].str.strip().str.lower() == "ok").astype(int)

    raw = u["detected"].str.strip().str.lower()
    det = raw.map(TRUE_STRINGS)
    det = det.fillna(pd.to_numeric(raw, errors="coerce")).fillna(0)
    u["gd_det"] = (det > 0).astype(int)
    unparsed = int((~raw.isin(TRUE_STRINGS) & pd.to_numeric(raw, errors="coerce").isna()).sum())
    if unparsed:
        warn(f"{unparsed} GuardDog 'detected' value(s) were unparseable and counted as 0")

    if ignore:
        if not findings:
            sys.exit("--ignore-paths needs --gd-findings to recompute GuardDog detection")
        f = pd.concat([read(p, ["package", "version", "label", "file"]).assign(corpus=t)
                       for p, t in findings], ignore_index=True)
        has = f[KEY].drop_duplicates().assign(_has=1)
        kept = drop_ignored(f, ignore)[KEY].drop_duplicates().assign(_kept=1)
        u = u.merge(has, on=KEY, how="left").merge(kept, on=KEY, how="left")
        # only units whose findings were ALL path-filtered lose their detection
        lost = (u["_has"] == 1) & (u["_kept"].isna())
        u.loc[lost, "gd_det"] = 0
    return collapse_rows(u[KEY + ["gd_ok", "gd_det"]])


def build(a, queries):
    ssf, all_q = load_ssf(split(a.ssf_audit), split(a.ssf_findings), queries, a.ignore_paths)
    gd = load_gd(split(a.gd_summary), split(a.gd_findings), a.ignore_paths)
    m = ssf.merge(gd, on=KEY, how="outer")
    for c in ["ssf_ok", "ssf_det", "gd_ok", "gd_det"]:
        m[c] = m[c].fillna(0).astype(int)
    one_sided = int(((m["ssf_ok"] == 0) & (m["gd_ok"] == 0)).sum())
    if one_sided:
        warn(f"{one_sided} unit(s) were analyzed by neither tool or exist in only one tool's files")
    return m, all_q


# ----------------------------------------------------------------- unit selection
def pick_rep(m):
    """One row per package. Preference order: analyzed by both tools, stable over
    prerelease, highest semver. (Choosing the version BEFORE checking success would
    drop a package whenever its top version failed in one tool.)"""
    def vk(v):
        try:
            return Version(v)
        except InvalidVersion:
            return Version("0")
    m = m.copy()
    m["_both"] = ((m["ssf_ok"] == 1) & (m["gd_ok"] == 1)).astype(int)
    m["_v"] = m["version"].map(vk)
    m["_pre"] = m["_v"].map(lambda v: v.is_prerelease)
    m = m.sort_values(["corpus", "package", "label", "_both", "_pre", "_v"],
                      ascending=[True, True, True, True, False, True])
    return (m.groupby(["corpus", "package", "label"], as_index=False).tail(1)
             .drop(columns=["_v", "_pre", "_both"]))


def apply_keep(m, path, col, verbose=True):
    raw = read(path, [col])[col]
    pkgs = [s.rsplit("__", 2)[0] for s in raw]          # <package>__<version>__<hash12>
    names = set(pkgs)
    names |= {n.replace("__", "/", 1) for n in pkgs if n.startswith("@")}   # scoped names
    if len(pkgs) != len(set(pkgs)):
        warn(f"{len(pkgs) - len(set(pkgs))} duplicate package name(s) in --keep file; "
             "multiple folders of one package are merged into one unit")
    mal = m[m["label"] == "malicious"]
    matched = set(mal.loc[mal["package"].isin(names), "package"])
    if verbose:
        print(f"--keep: {len(matched)} of {len(set(pkgs))} kept package names matched a malicious row")
        missing = sorted(set(pkgs) - matched)
        if missing:
            warn(f"unmatched --keep names (first 5): {missing[:5]}")
    return m[(m["label"] != "malicious") | m["package"].isin(names)]


def prepare(a, queries, verbose=True):
    m, all_q = build(a, queries)
    if a.unit == "package":
        m = pick_rep(m)
    if a.keep:
        m = apply_keep(m, a.keep, a.keep_col, verbose)
    return m, all_q


# ----------------------------------------------------------------- metrics
def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def summarize(d, det):
    y, p = (d["label"] == "malicious").astype(int), d[det]
    tp = int(((y == 1) & (p == 1)).sum())
    fn = int(((y == 1) & (p == 0)).sum())
    fp = int(((y == 0) & (p == 1)).sum())
    tn = int(((y == 0) & (p == 0)).sum())
    nan = float("nan")
    rec = tp / (tp + fn) if tp + fn else nan
    fpr = fp / (fp + tn) if fp + tn else nan
    prec = tp / (tp + fp) if tp + fp else nan
    f1 = 2 * prec * rec / (prec + rec) if prec == prec and rec == rec and prec + rec else nan
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / den if den else nan
    rl, rh = wilson(tp, tp + fn)
    fl, fh = wilson(fp, fp + tn)
    return dict(TP=tp, FN=fn, FP=fp, TN=tn, recall=rec, recall_lo=rl, recall_hi=rh,
                FPR=fpr, FPR_lo=fl, FPR_hi=fh, precision=prec, F1=f1, MCC=mcc)


def evaluate(m, population, tools=(("SSF", "ssf"), ("GuardDog", "gd"))):
    rows = []
    for tool, pre in tools:
        sel = m
        if population == "common":
            sel = sel[(sel["ssf_ok"] == 1) & (sel["gd_ok"] == 1)]
        elif population == "own":
            sel = sel[sel[pre + "_ok"] == 1]
        if sel.empty:
            continue
        r = summarize(sel, pre + "_det")
        r.update(tool=tool)
        rows.append(r)
    return pd.DataFrame(rows)


def mcnemar(d, name):
    b = int(((d["ssf_det"] == 1) & (d["gd_det"] == 0)).sum())
    c = int(((d["ssf_det"] == 0) & (d["gd_det"] == 1)).sum())
    p = binomtest(min(b, c), b + c, 0.5).pvalue if b + c else float("nan")
    print(f"  {name:<10} n={len(d):<5} SSF-only={b:<5} GuardDog-only={c:<5} exact McNemar p={p:.3g}")


def show(df, extra=()):
    cols = ["tool", "TP", "FN", "FP", "TN", "recall", "FPR", "precision", "F1", "MCC"]
    cols = [c for c in extra] + cols
    out = df[cols].copy()
    out["recall"] = [f"{r:.3f} [{lo:.3f}-{hi:.3f}]" for r, lo, hi in zip(df.recall, df.recall_lo, df.recall_hi)]
    out["FPR"] = [f"{r:.3f} [{lo:.3f}-{hi:.3f}]" for r, lo, hi in zip(df.FPR, df.FPR_lo, df.FPR_hi)]
    for c in ["precision", "F1", "MCC"]:
        out[c] = out[c].map(lambda x: f"{x:.3f}")
    pd.set_option("display.width", 220)
    print(out.to_string(index=False))


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssf-audit", nargs="+", required=True)
    ap.add_argument("--ssf-findings", nargs="+", required=True)
    ap.add_argument("--gd-summary", nargs="+", required=True)
    ap.add_argument("--gd-findings", nargs="*", default=[])
    ap.add_argument("--queries", nargs="*", help="restrict SSF detection to these queries")
    ap.add_argument("--ignore-paths", default="",
                    help=r"regex; findings whose file matches are ignored, e.g. '(^|/)(test|tests|__tests__|e2e|examples?|fixtures?|docs?)/'")
    ap.add_argument("--unit", choices=["package", "version"], default="package")
    ap.add_argument("--population", choices=["common", "all", "own"], default="common",
                    help="common: units analyzed by both tools | all: failures count as 'no detection' | own: each tool on its own analyzed units")
    ap.add_argument("--keep", help="CSV of malicious units to keep (e.g. malicious_families.csv)")
    ap.add_argument("--keep-col", default="rep_folder")
    ap.add_argument("--per-query", action="store_true")
    ap.add_argument("--out-dir", default="results",
                    help="root output folder; files go to <out-dir>/<population>/")
    ap.add_argument("--out-prefix", default="confusion")
    a = ap.parse_args()

    m, all_q = prepare(a, a.queries)

    print("\nUNIVERSE (units per corpus/label, and how many each tool analyzed)")
    g = m.groupby(["corpus", "label"]).agg(units=("package", "size"), ssf_analyzed=("ssf_ok", "sum"),
                                           gd_analyzed=("gd_ok", "sum"))
    print(g.to_string())
    both = m[(m["ssf_ok"] == 1) & (m["gd_ok"] == 1)]
    print(f"analyzed by both: {len(both)} of {len(m)}\n")

    if not (m["label"] == "malicious").any():
        sys.exit("ERROR: no malicious units in the universe; recall/MCC would be NaN. "
                 "Check tags, labels and --keep before going further.")
    if not (m["label"] == "benign").any():
        warn("no benign units in the universe; FPR/precision will be NaN")

    res = evaluate(m, a.population)
    if res.empty:
        sys.exit("ERROR: no units left after applying --population; check the UNIVERSE table above.")
    print(f"CONFUSION MATRICES (unit={a.unit}, population={a.population}); positive = malicious; 95% Wilson CIs")
    show(res)

    # McNemar is only valid on units both tools analyzed, whatever --population says
       # Paired test on the same population the metrics use
    pop = m if a.population == "all" else both
    label = ("all units, failure = no detection" if a.population == "all"
             else "units analyzed by both tools")
    print(f"\nPAIRED COMPARISON ({label})")
    mcnemar(pop[pop["label"] == "malicious"], "malicious")
    mcnemar(pop[pop["label"] == "benign"], "benign")

    # Output folder: <out-dir>/<population>/
    out = Path(a.out_dir) / a.population
    out.mkdir(parents=True, exist_ok=True)
    base = out / a.out_prefix

    if a.per_query:
        print("\nSSF PER QUERY")
        rows = []
        for q in all_q:
            mq, _ = prepare(a, [q], verbose=False)
            r = evaluate(mq, a.population, tools=(("SSF", "ssf"),))
            if not r.empty:
                rows.append(r.assign(query=q))
        if rows:
            pq = pd.concat(rows, ignore_index=True)
            show(pq, extra=["query"])
            pq.to_csv(f"{base}_per_query.csv", index=False)

    res.to_csv(f"{base}_summary.csv", index=False)
    m.to_csv(f"{base}_units.csv", index=False)
    print(f"\nwrote {base}_summary.csv and {base}_units.csv (per-unit detections for FP/FN audit)")


if __name__ == "__main__":
    main()