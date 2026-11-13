#!/usr/bin/env python3
"""
RQ4 analysis, implemented as the Methods section describes it.

  1) families   content-hash family id for every package version
       uv run rq4_statistical_check.py families --dataset ../npm_dataset_io    --out family_benign.csv
       uv run rq4_statistical_check.py families --dataset ../temporal_corups   --out family_malicious.csv

  2) rq4        deduplicate to one representative per family and label, then run
                (a) five NB2 models, one per API category (Bonferroni over the five), and
                (b) size-stratified Mantel-Haenszel for the ten category pairs (Holm over ten)
       uv run rq4_statistical_check.py rq4 --analysis analysis_latest.csv \
           --fam-benign family_benign.csv --fam-malicious family_malicious.csv --drop-unmatched --out-prefix rq4

  3) zero-audit are zero counts real zeros? (grep-style audit of the sources)
       uv run rq4_statistical_check.py zero-audit --csv benign.csv --dataset ../npm_dataset_io --sample 300

Methods-to-code map
  family id      sha256 of the sorted per-file sha256 hashes, whitespace removed, .d.ts and
                 excluded directories skipped, first 16 hex characters; packages without source
                 files get a unique 'empty::' id and are never merged.
  representative per (family id, label) keep the package with the largest AST node count
                 (ties broken by package name, so the choice is reproducible).
  NB2            log E[Y_ij] = b0 + b1*M_i + b2*log(1 + S_i); IRR = exp(b1); Bonferroni across
                 the five categories; a model that does not converge is non-estimable.
  CMH            presence/absence per category, strata = pooled quantile bands of log(1 + S_i),
                 Mantel-Haenszel pooled log OR per corpus, z-test on the difference, Holm over ten.

The pairwise interaction term (beta_3) that appeared in the old Table 8 is NOT computed here,
because the Methods do not define it.
"""
import argparse
import hashlib
import os
import random
import re
import sys
from itertools import combinations

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, ".")
COLS = list("ABCDE")                       # API categories in the analysis CSV


def pid_of(name, version):
    """Same package id the extractor writes in its 'Package' column."""
    safe = name.replace("/", "__")
    return f"{safe}_v{version}" if version else safe


def load_extractor():
    try:
        import calculate_senstive_api_call_script.extract_api_counts as ex
    except ImportError:
        try:
            import extract_api_counts_v3 as ex
        except ImportError:
            sys.exit("cannot import the extractor (extract_api_counts_fixed or extract_api_counts_v3)")
    return ex


# ------------------------------------------------------------------ 1) families
def cmd_families(a):
    ex = load_extractor()
    rows = []
    for name, version, path, *_ in ex.enumerate_units(a.dataset, "auto"):
        hashes = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ex.EXCLUDE_DIRS]
            for f in sorted(files):
                if not f.endswith(ex.SRC_EXT) or f.endswith(".d.ts"):
                    continue
                try:
                    with open(os.path.join(root, f), "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                data = re.sub(rb"\s+", b"", data)          # whitespace-insensitive
                hashes.append(hashlib.sha256(data).hexdigest())
        pid = pid_of(name, version)
        if hashes:
            fam = hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()[:16]
        else:
            fam = "empty::" + pid                            # never merge empty packages
        rows.append((pid, fam, len(hashes)))

    out = pd.DataFrame(rows, columns=["Package", "family_id", "n_source_files"])
    out.to_csv(a.out, index=False)
    sizes = out.groupby("family_id").size().sort_values(ascending=False)
    print(f"{len(out)} package versions -> {len(sizes)} distinct families")
    print(f"families with more than one member: {(sizes > 1).sum()} | largest: {sizes.head(5).tolist()}")
    print(f"wrote {a.out}")
    print("NOTE: exact-content clones only. Near-duplicates (small edits) get different keys.")


# ------------------------------------------------------------------ shared loading
def load_analysis(path, size):
    df = pd.read_csv(path)
    want = {"package": "Package", "label": "label", size.lower(): size}
    want.update({c.lower(): c for c in COLS})
    df = df.rename(columns={c: want[c.strip().lower()] for c in df.columns
                            if c.strip().lower() in want})
    for c in ["Package", "label", size] + COLS:
        if c not in df.columns:
            sys.exit(f"missing column '{c}' in {path}")

    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(["benign", "malicious"])].copy()
    print("rows read:", df["label"].value_counts().to_dict())

    if "file_count" in df.columns:                           # malformed entries: zero source files
        df = df[pd.to_numeric(df["file_count"], errors="coerce") > 0]
    for c in [size] + COLS:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=[size] + COLS)                     # unparseable AST metrics
    df = df.drop_duplicates("Package")
    print("analysis cohort:", df["label"].value_counts().to_dict(),
          "(the Methods report 867 benign and 1,494 malicious)")
    return df


def strip_version(pid):
    return pid.rsplit("_v", 1)[0] if "_v" in pid else pid


def dedup_families(df, fam_benign, fam_malicious, size, drop_unmatched=False):
    exact, by_base = {}, {}
    for path in (fam_benign, fam_malicious):
        if not path or not os.path.exists(path):
            sys.exit(f"missing family file: {path}")
        t = pd.read_csv(path)
        for p, f in zip(t["Package"], t["family_id"]):
            exact[p] = f
            by_base.setdefault(strip_version(p), set()).add(f)
    df = df.copy()
    ids, n_fallback = [], 0
    for p in df["Package"]:
        if p in exact:
            ids.append(exact[p])
        elif len(by_base.get(p, ())) == 1:          # all versions share one family
            ids.append(next(iter(by_base[p])))
            n_fallback += 1
        else:
            ids.append(None)
    df["family_id"] = ids
    unmatched = df.loc[df["family_id"].isna(), "Package"].tolist()
    if unmatched:
        print("no unique family id for:", unmatched[:20])
        if not drop_unmatched:
            sys.exit(f"{len(unmatched)} packages unmatched; rerun with --drop-unmatched to exclude them")
        print(f"excluding {len(unmatched)} unmatched packages from RQ4 (state this in the Methods)")
        df = df[df["family_id"].notna()]
    print(f"matched by name without version: {n_fallback}")
    df = df.sort_values([size, "Package"], ascending=[False, True], kind="mergesort")
    out = df.drop_duplicates(subset=["family_id", "label"])
    print("after family deduplication:", out["label"].value_counts().to_dict(),
          "(the Methods report 517 benign and 881 malicious)")
    return out


# ------------------------------------------------------------------ 2a) NB2, one model per category
def run_nb2(df, size, out_path):
    import statsmodels.api as sm

    d = df.copy()
    d["log_size"] = np.log1p(d[size].astype(float))
    d["M"] = (d["label"] == "malicious").astype(float)
    X = sm.add_constant(d[["M", "log_size"]])

    rows = []
    for c in COLS:
        row = dict(category=c, n=len(d), estimable=False, converged=False, method="",
                   beta_malicious=np.nan, se=np.nan, IRR=np.nan, IRR_lo=np.nan,
                   IRR_hi=np.nan, p=np.nan, share_zero_ben=np.nan, share_zero_mal=np.nan,
                   note="")
        y = d[c].astype(float).to_numpy()
        row["share_zero_ben"] = float((y[d["M"] == 0] == 0).mean())
        row["share_zero_mal"] = float((y[d["M"] == 1] == 0).mean())
        if np.unique(y).size < 2:
            row["note"] = "no variance"
            rows.append(row)
            continue

        try:                                                 # Poisson fit gives start values
            start = np.append(sm.Poisson(y, X).fit(disp=0).params.to_numpy(), 0.5)
        except Exception:
            start = None

        res = None
        for meth in ("bfgs", "lbfgs", "newton", "nm"):       # first method that converges
            try:
                r = sm.NegativeBinomial(y, X, loglike_method="nb2").fit(
                    start_params=start, method=meth, maxiter=2000, disp=0)
            except Exception:
                continue
            converged = bool(getattr(r, "mle_retvals", {}).get("converged", False))
            if converged and np.isfinite(r.bse["M"]) and np.isfinite(r.pvalues["M"]):
                res, row["method"] = r, meth
                break
        if res is None:                                      # non-estimable per the Methods
            row["note"] = "no convergence with a finite standard error (bfgs, lbfgs, newton, nm)"
            rows.append(row)
            continue

        b = float(res.params["M"])
        ci = res.conf_int().loc["M"]
        row.update(estimable=True, converged=True, beta_malicious=b, se=float(res.bse["M"]),
                   IRR=float(np.exp(b)), IRR_lo=float(np.exp(ci[0])),
                   IRR_hi=float(np.exp(ci[1])), p=float(res.pvalues["M"]))
        rows.append(row)

    res = pd.DataFrame(rows)
    res["p_bonferroni"] = (res["p"] * len(COLS)).clip(upper=1.0)   # five planned comparisons
    res.to_csv(out_path, index=False)
    pd.set_option("display.width", 240)
    print("\nNB2 (malicious vs benign at equal AST size), Bonferroni over 5 categories")
    print(res.drop(columns=["note"]).round(4).to_string(index=False))
    for r_ in res.itertuples():
        if r_.note:
            print(f"  {r_.category}: {r_.note}")
    print(f"wrote {out_path}")
    return res


# ------------------------------------------------------------------ 2b) size-stratified CMH
def run_cmh(df, size, bins, min_stratum, out_path):
    import statsmodels.api as sm
    from statsmodels.stats.multitest import multipletests

    d = df.copy()
    ls = np.log1p(d[size].to_numpy(float))
    edges = np.unique(np.quantile(ls, np.linspace(0, 1, bins + 1)))   # pooled across both corpora
    d["band"] = np.digitize(ls, edges[1:-1])

    def group_est(g, x, y):
        tabs = []
        for _, gb in g.groupby("band"):
            xp, yp = gb[x] > 0, gb[y] > 0
            t = np.array([[(xp & yp).sum(), (xp & ~yp).sum()],
                          [(~xp & yp).sum(), (~xp & ~yp).sum()]])
            if t.sum() >= min_stratum and t.sum(0).min() > 0 and t.sum(1).min() > 0:
                tabs.append(t)
        if len(tabs) < 2:
            return None
        try:
            with np.errstate(all="ignore"):
                st = sm.stats.StratifiedTable(tabs)
                lo, se = float(st.logodds_pooled), float(st.logodds_pooled_se)
            if not (np.isfinite(lo) and np.isfinite(se) and se > 0):
                return None
            p0 = float(st.test_null_odds(correction=True).pvalue)
        except Exception:
            return None
        return dict(lo=lo, se=se, n=int(sum(t.sum() for t in tabs)), k=len(tabs), p=p0)

    rows = []
    for x, y in combinations(COLS, 2):
        b = group_est(d[d.label == "benign"], x, y)
        m = group_est(d[d.label == "malicious"], x, y)
        row = dict(pair=f"{x}-{y}", ok=b is not None and m is not None)
        if row["ok"]:
            diff = m["lo"] - b["lo"]
            z = diff / np.sqrt(m["se"] ** 2 + b["se"] ** 2)
            row.update(logOR_ben=b["lo"], se_ben=b["se"], logOR_mal=m["lo"], se_mal=m["se"],
                       diff=diff, z=z, p=2 * stats.norm.sf(abs(z)),
                       n_ben=b["n"], n_mal=m["n"], strata_ben=b["k"], strata_mal=m["k"],
                       cmh_p_ben=b["p"], cmh_p_mal=m["p"])
        rows.append(row)

    res = pd.DataFrame(rows)
    p = res["p"].fillna(1.0).to_numpy() if "p" in res else np.ones(len(res))
    res["p_holm"] = multipletests(p, method="holm")[1]          # ten planned comparisons
    res.loc[~res["ok"], "p_holm"] = np.nan
    res.to_csv(out_path, index=False)
    pd.set_option("display.width", 220)
    show = [c for c in ["pair", "logOR_ben", "logOR_mal", "diff", "p", "p_holm", "n_ben", "n_mal",
                        "strata_ben", "strata_mal"] if c in res.columns]
    print(f"\nSize-stratified MH, {bins} pooled size bands, Holm over {len(res)} pairs")
    print(res[show].round(4).to_string(index=False))
    print(f"wrote {out_path}")
    print("diff = log-OR(malicious) - log-OR(benign), each Mantel-Haenszel pooled across size bands.")
    return res


def cmd_rq4(a):
    df = load_analysis(a.analysis, a.size)
    df = dedup_families(df, a.fam_benign, a.fam_malicious, a.size, a.drop_unmatched)
    run_nb2(df, a.size, f"{a.out_prefix}_nb2.csv")
    run_cmh(df, a.size, a.bins, a.min_stratum, f"{a.out_prefix}_cmh.csv")


# ------------------------------------------------------------------ 3) zero audit
CHECKS = {
    "OS & File System": re.compile(
        r"""(?:require\(\s*|from\s+)['"](?:node:)?(?:fs|os)(?:/promises)?['"]"""),
    "Process Execution": re.compile(r"child_process|\beval\s*\(|new\s+Function\s*\("),
    "Network & HTTP": re.compile(
        r"""(?:require\(\s*|from\s+)['"](?:node:)?https?['"]|\bfetch\s*\(|XMLHttpRequest|\baxios\b"""),
    "Serialization & Buffer": re.compile(r"\bBuffer\b|JSON\.(?:parse|stringify)"),
    "Encoding & Obfuscation": re.compile(
        r"encodeURIComponent|decodeURIComponent|\bbtoa\s*\(|\batob\s*\(|\bescape\s*\(|\bunescape\s*\("),
}


def cmd_audit(a):
    ex = load_extractor()
    path_of = {pid_of(n, v): p for n, v, p, *_ in ex.enumerate_units(a.dataset, "auto")}
    df = pd.read_csv(a.csv)
    if "file_count" in df.columns:
        df = df[df["file_count"] > 0]
    df = df.drop_duplicates("Package")
    label = str(df["Label"].iloc[0]) if "Label" in df.columns else "?"

    rng = random.Random(a.seed)
    ids = [p for p in df["Package"] if p in path_of]
    rng.shuffle(ids)
    ids = ids[: a.sample]
    sub = df.set_index("Package").loc[ids]

    n_zero = {c: 0 for c in ex.CATS}
    n_hit = {c: 0 for c in ex.CATS}
    suspects = []

    for pid in ids:
        zeros = [c for c in ex.CATS if sub.loc[pid, c] == 0]
        for c in zeros:
            n_zero[c] += 1
        pending = set(zeros)
        for root, dirs, files in os.walk(path_of[pid]):
            if not pending:
                break
            dirs[:] = [d for d in dirs if d not in ex.EXCLUDE_DIRS]
            for f in files:
                if not pending:
                    break
                if not f.endswith(ex.SRC_EXT) or f.endswith(".d.ts"):
                    continue
                fp = os.path.join(root, f)
                try:
                    if os.path.getsize(fp) > 10 * 1024 * 1024:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for c in list(pending):
                    m = CHECKS[c].search(text)
                    if m:
                        line = text.count("\n", 0, m.start()) + 1
                        snip = re.sub(r"\s+", " ", text[max(0, m.start() - 60): m.end() + 60])
                        suspects.append((pid, c, os.path.relpath(fp, path_of[pid]), line, snip))
                        n_hit[c] += 1
                        pending.discard(c)

    print(f"\nZero-count audit, group = {label}, sampled packages = {len(ids)}")
    print(f"{'category':<26}{'zero-count pkgs':>16}{'with indicator':>16}{'rate':>8}")
    for c in ex.CATS:
        r = n_hit[c] / n_zero[c] if n_zero[c] else float("nan")
        print(f"{c:<26}{n_zero[c]:>16}{n_hit[c]:>16}{r:>8.1%}")

    out = pd.DataFrame(suspects, columns=["Package", "category", "file", "line", "snippet"])
    out_path = f"zero_audit_{label}.csv"
    out.to_csv(out_path, index=False)
    print(f"\nwrote {out_path} ({len(out)} suspects)")
    print("An indicator is NOT proof of a miss (unused imports, strings, comments also match).")
    for row in out.sample(min(15, len(out)), random_state=a.seed).itertuples():
        print(f"  [{row.category}] {row.Package} {row.file}:{row.line}  ...{row.snippet[:140]}...")


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)

    f = sp.add_parser("families")
    f.add_argument("--dataset", required=True)
    f.add_argument("--out", required=True)
    f.set_defaults(fn=cmd_families)

    r = sp.add_parser("rq4")
    r.add_argument("--analysis", default="analysis_latest.csv")
    r.add_argument("--fam-benign", default="family_benign.csv")
    r.add_argument("--fam-malicious", default="family_malicious.csv")
    r.add_argument("--size", default="ast_nodes")
    r.add_argument("--bins", type=int, default=8)
    r.add_argument("--min-stratum", type=int, default=10)
    r.add_argument("--out-prefix", default="rq4")
    r.add_argument("--drop-unmatched", action="store_true")
    r.set_defaults(fn=cmd_rq4)

    z = sp.add_parser("zero-audit")
    z.add_argument("--csv", required=True, help="extractor output CSV (benign.csv or malicious.csv)")
    z.add_argument("--dataset", required=True)
    z.add_argument("--sample", type=int, default=300)
    z.add_argument("--seed", type=int, default=42)
    z.set_defaults(fn=cmd_audit)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()