#!/usr/bin/env python3
"""
RQ2/RQ3 evidence in one run:
  A  confusion matrices, all view          
  B  confusion matrices, common view
  C  package-clustered bootstrap for benign FPR
  D  what SSF misses that GuardDog catches (GuardDog rules behind them)
  E  SSF ablation by query (alone / unique / drop-one) and false positives per query
Edit only the CONFIG block.
"""
import numpy as np
import pandas as pd
from scipy.stats import binomtest

# ============================== CONFIG ======================================
UNITS = "./results/all/temporal_all_units.csv"   # corpus,package,version,label,ssf_ok,ssf_det,gd_ok,gd_det
SSF_ALERTS = [("../results/ssf-temporal/ssf_large_scale_npm_io.csv", "benign"),
              ("../results/ssf-temporal/ssf_large_scale_temporal.csv", "malicious")]
GD_ALERTS = [("../results/guarddog-temporal/guarddog_large_findings_npm_io.csv", "benign"),
             ("../results/guarddog-temporal/guarddog_large_findings_temporal.csv", "malicious")]
QUERY_COL = "query"      # column naming the SSF query in the SSF alert files
RULE_COL = "rule"        # column naming the GuardDog rule in the GuardDog files
N_BOOT = 2000
# ============================================================================


def make_key(df):
    """malicious: package only (one version each); benign: package|version."""
    pkg = df["package"].astype(str).str.strip()
    ver = df["version"].astype(str).str.strip() if "version" in df.columns else ""
    return np.where(df["label"] == "malicious", pkg, pkg + "|" + ver)


def load_many(pairs):
    parts = []
    for path, label in pairs:
        d = pd.read_csv(path, dtype=str, keep_default_na=False)
        d.columns = [c.strip() for c in d.columns]
        d["label"] = label                       # the file decides the label
        parts.append(d)
    d = pd.concat(parts, ignore_index=True)
    d["key"] = make_key(d)
    return d


def wil(k, n):
    lo, hi = binomtest(k, n).proportion_ci(0.95, method="wilson")
    return f"{k}/{n} = {100*k/n:.1f}% [{100*lo:.1f}-{100*hi:.1f}]"


def mcnemar(a, b):
    return binomtest(min(a, b), a + b, 0.5).pvalue if a + b else 1.0


# ---------------------------------------------------------------- units ----
u = pd.read_csv(UNITS, dtype=str, keep_default_na=False)
u.columns = [c.strip() for c in u.columns]
for c in ("ssf_ok", "ssf_det", "gd_ok", "gd_det"):
    u[c] = pd.to_numeric(u[c], errors="coerce").fillna(0).astype(int)
u["label"] = u["label"].str.strip().str.lower()
u["mal"] = u["label"] == "malicious"
u["key"] = make_key(u)
if u["key"].duplicated().any():
    print("WARNING: duplicate unit keys:", u.loc[u["key"].duplicated(), "key"].head().tolist())


def block(name, d):
    print(f"\n== {name}: {int(d.mal.sum())} malicious, {int((~d.mal).sum())} benign ==")
    for t in ("ssf", "gd"):
        m, b = d[d.mal], d[~d.mal]
        tp, fp = int(m[f"{t}_det"].sum()), int(b[f"{t}_det"].sum())
        print(f"{t:4s} TP={tp} FN={len(m)-tp} FP={fp} TN={len(b)-fp}")
        print(f"     recall {wil(tp, len(m))} | FPR {wil(fp, len(b))}")
    for lab, g in d.groupby("label"):
        a = int(((g.ssf_det == 1) & (g.gd_det == 0)).sum())
        b = int(((g.ssf_det == 0) & (g.gd_det == 1)).sum())
        print(f"  {lab}: SSF-only={a} GD-only={b} exact McNemar p={mcnemar(a, b):.3g}")


block("A: ALL (failed SSF analysis = no detection)", u)
block("B: COMMON (analyzed by both tools)", u[(u.ssf_ok == 1) & (u.gd_ok == 1)])

# ------------------------------------------------- C: clustered bootstrap ---
rng = np.random.default_rng(0)
ben = u[~u.mal].copy()
ben["pkg"] = ben["package"].str.strip()
groups = {p: g for p, g in ben.groupby("pkg")}
pkgs = list(groups)
print("\n== C: benign FPR, bootstrap resampling packages ==")
for t in ("ssf_det", "gd_det"):
    r = [pd.concat([groups[p] for p in rng.choice(pkgs, len(pkgs))])[t].mean() for _ in range(N_BOOT)]
    lo, hi = np.percentile(r, [2.5, 97.5])
    print(f"{t}: FPR {100*ben[t].mean():.1f}%  CI [{100*lo:.1f}, {100*hi:.1f}]")

# ------------------------------------------------------- D: SSF misses ------
gd = load_many(GD_ALERTS)
print("\n== D: malicious detected by GuardDog but not by SSF ==")
miss = u[u.mal & (u.gd_det == 1) & (u.ssf_det == 0)]
n_fail = int((miss.ssf_ok == 0).sum())
print(f"{len(miss)} packages: {n_fail} SSF could not analyze, {len(miss)-n_fail} analyzed with no alert")
if RULE_COL in gd.columns:
    m = gd.merge(miss[["key"]], on="key")
    print("GuardDog rules on these packages (distinct packages per rule):")
    print(m.groupby(RULE_COL)["key"].nunique().sort_values(ascending=False).head(20).to_string())
    miss.merge(m.groupby("key")[RULE_COL].apply(lambda s: ";".join(sorted(set(s)))).reset_index(),
               on="key", how="left").to_csv("ssf_missed_by_ssf_temporal.csv", index=False)
else:
    print(f"column '{RULE_COL}' not in GuardDog files; columns are: {gd.columns.tolist()}")
    miss.to_csv("ssf_missed_by_ssf_temporal.csv", index=False)
print("wrote ssf_missed_by_ssf_temporal.csv")

# ------------------------------------------------------ E: SSF ablation -----
sa = load_many(SSF_ALERTS)
if QUERY_COL not in sa.columns:
    raise SystemExit(f"column '{QUERY_COL}' not in SSF files; columns are: {sa.columns.tolist()}")
mal = set(u[u.mal]["key"]); benk = set(u[~u.mal]["key"]); universe = mal | benk
hits = {q: set(x["key"]) & universe for q, x in sa.groupby(QUERY_COL)}
full = set().union(*hits.values())

print("\n== E: SSF ablation by query ==")
chk_m, chk_b = len(full & mal), len(full & benk)
exp_m, exp_b = int(u[u.mal].ssf_det.sum()), int(u[~u.mal].ssf_det.sum())
print(f"alerts give {chk_m} malicious / {chk_b} benign units; units file says {exp_m} / {exp_b} "
      f"-> {'OK' if (chk_m, chk_b) == (exp_m, exp_b) else 'MISMATCH (check keys / files before using E)'}")

rows = []
for q in hits:
    rest = set().union(*[h for k, h in hits.items() if k != q]) if len(hits) > 1 else set()
    rows.append(dict(query=q,
                     alone_TP=len(hits[q] & mal), alone_FP=len(hits[q] & benk),
                     unique_TP=len((full - rest) & mal),
                     unique_FP=len((full - rest) & benk),
                     recall_without=round(len(rest & mal) / len(mal), 3),
                     FPR_without=round(len(rest & benk) / len(benk), 4)))
abl = pd.DataFrame(rows).sort_values("alone_TP", ascending=False)
print(f"full set: recall {len(full & mal)}/{len(mal)}, FPR {len(full & benk)}/{len(benk)}")
print(abl.to_string(index=False))
abl.to_csv("ssf_query_ablation_temporal.csv", index=False)
print("wrote ssf_query_ablation_temporal.csv")

# ======= F: GuardDog by rule category, derived from the per-rule alerts =======
MISSED = "ssf_missed_by_ssf_temporal.csv"      # the file block D wrote (rename if you renamed it)
rules = gd.groupby("key")[RULE_COL].apply(lambda s: set(";".join(s).split(";")) - {""})
def det_cfg(prefix):
    return u["key"].map(lambda k: any(r.startswith(prefix) for r in rules.get(k, set()))).astype(int)
u["gd_threat"] = det_cfg("threat-")
u["gd_capability"] = det_cfg("capability-")
print("\n== F: GuardDog by rule category ==")
print("sanity: default GuardDog detections differ from 'any rule' in",
      int((u.gd_det != u["key"].map(lambda k: int(len(rules.get(k, set())) > 0))).sum()), "units")
for name, col in (("GuardDog default", "gd_det"), ("GuardDog threat-only", "gd_threat"),
                  ("GuardDog capability-only", "gd_capability"), ("SSF", "ssf_det")):
    m, b = u[u.mal], u[~u.mal]
    print(f"{name:26s} recall {wil(int(m[col].sum()), len(m))} | FPR {wil(int(b[col].sum()), len(b))}")
for lab, g in u.groupby("label"):
    a = int(((g.ssf_det == 1) & (g.gd_threat == 0)).sum()); c = int(((g.ssf_det == 0) & (g.gd_threat == 1)).sum())
    print(f"  {lab}: SSF vs GuardDog-threat  SSF-only={a} GD-only={c} McNemar p={mcnemar(a, c):.3g}")

# ======= G: worm-like group (GuardDog self-propagation rule) ==================
selfprop = u["key"].map(lambda k: "threat-runtime-self-propagation" in rules.get(k, set())).astype(bool)
W = u[u.mal & selfprop]; rest = u[u.mal & ~selfprop]
print(f"\n== G: {len(W)} malicious packages with the self-propagation rule; SSF detects {int(W.ssf_det.sum())} ==")
print("recall without them:", *[f"{t}: {wil(int(rest[t].sum()), len(rest))}" for t in ("ssf_det", "gd_det", "gd_threat")], sep="\n  ")
tok = W["key"].str.replace(r"__.*$", "", regex=True).str.split(r"[-_]").str[-1]
print("most common name endings in this group:\n", tok.value_counts().head(12).to_string())
print("sample names:", W["key"].str.replace(r"__.*$", "", regex=True).sample(min(12, len(W)), random_state=0).tolist())

# ======= H: how strong are GuardDog's 'only' detections ======================
mm = pd.read_csv(MISSED)
has_t = mm["rule"].fillna("").str.contains("threat-")
print(f"\n== H: {int(has_t.sum())} of {len(mm)} GuardDog-only detections have a threat rule; "
      f"{int((~has_t).sum())} are capability-only ==")
print(mm.assign(threat=has_t).groupby("ssf_ok").threat.agg(["sum", "size"]))