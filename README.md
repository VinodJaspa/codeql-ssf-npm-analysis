# Semantic Stability Framework (SSF) for npm Malware Detection

This repository contains the full replication package, custom CodeQL queries, statistical models, and research artifacts for the paper: **"Decoding Security Incidents in npm Repositories: An Empirical Study on Obfuscated Threats and Sensitive API Misuse Using CodeQL."**

## 📌 Repository Overview

The repository is structured to match each stage of our empirical analysis workflow, from dataset acquisition to individual research question (RQ1–RQ4) evaluation:

```text
codeql-ssf-npm-analysis/
├── benign-packages-download-script/    # Automated fetching of public npm benign baseline
├── codeql-custom-queries-javascript/    # 7-query SSF CodeQL suite (taint flow, structural, hooks)
│   ├── os-fingerprinting-exfiltration.ql
│   ├── computed-property-access.ql
│   ├── pre-post-install-scripts.ql
│   ├── network-response-dynamic-exec.ql
│   ├── obfuscated-payload-detonation.ql
│   ├── pre-post-source-sink-exec.ql
│   └── credential-harvest-exfil.ql
├── confusion_matrix/                   # Evaluation metric scripts (Recall, FPR, McNemar tests)
├── corpora/                            # Corpus reference lists (Discovery, Validation, Temporal)
├── guarddog/                           # GuardDog benchmark scan runners and baseline configs
├── helper/                             # Utility modules and environment helpers
├── make-dataset/                       # Dataset hygiene, parsing, and preprocessing pipelines
├── results/                            # Raw JSON/CSV query execution outputs & logs
├── rq-1/                               # RQ1: Coverage & analysis cost processing
├── rq-2-3-ablation-study/              # RQ2 & RQ3: Baseline comparisons & query ablation
├── rq-4/                               # RQ4: NB2 regressions & CMH stratification analysis
├── scripts/                            # Core extraction and statistical validation scripts
├── ssf-analysis/                       # SSF analysis engine and runners
│   ├── codeql_script.py                # Database creation & batch query evaluation runner
│   └── README-SSF-DESIGN-PRINCIPAL.md  # Detailed query design principles documentation
├── pyproject.toml                      # Project metadata and dependencies (uv / pip)
├── uv.lock                             # Locked environment dependency versions
└── README.md                           # Repository Documentation
```

---

## ⚙️ Environment & Requirements

### System Setup
* **OS:** Debian GNU/Linux 13 (trixie) / macOS (Apple Silicon)
* **CodeQL CLI:** Version 2.23.6 or later
* **Package Manager:** [`uv`](https://github.com/astral-sh/uv) (recommended) or standard Python `pip`
* **Python:** 3.10+


### Quickstart Installation

Using `uv` (recommended):
```bash
uv sync
```
---

## 🚀 Step-by-Step Execution Guide

### 1. Execute CodeQL Analysis Engine
To run database creation and batch evaluation across tarball corpora:
```bash
python ssf-analysis/codeql_script.py \
  --source-dir ./dataset-list \
  --queries-dir ./codeql-custom-queries-javascript \
  --output-dir ./results
```

### 2. Run RQ1 (Coverage & Cost Analysis)
Quantify CodeQL database build outcomes and timing metrics:
```bash
python rq-1/analyze_coverage_cost.py --results-dir ./results
```

### 3. Run RQ2 & RQ3 (Benchmarking & Ablation Study)
Generate confusion matrices, Wilson confidence intervals, and query ablation metrics against GuardDog:
```bash
python rq-2-3-ablation-study/evaluate_benchmarks.py \
  --ssf-results ./results \
  --guarddog-results ./guarddog/results
```

### 4. Run RQ4 (Scale-Controlled Regressions & CMH Analysis)
Reproduce clone-aware Negative Binomial regressions (NB2) and size-stratified Cochran-Mantel-Haenszel tests:
```bash
Rscript rq-4/statistical_models.R --data ./rq-4/deduplicated_families.csv
```

---

## 📊 Evaluation Corpora Summary

1. **Discovery Set ($N=74$):** Backstabber's Knife Collection (*Ohm et al.*)
2. **Validation Set ($N=95$ malicious, $887$ benign versions):** MALOSS dataset (*Duan et al.*) & npm baseline
3. **Specialized I/O & CLI Corpus ($N=874$):** Keyword-selected developer tooling (`cli`, `sdk`, `build-tool`)
4. **Temporal Hold-Out Corpus ($N=1,500$):** Post-2023 Datadog malicious software dataset

---

## 📜 License & Anonymity

This repository is distributed under the **MIT License**.

> **Double-Blind Review Notice:** This repository has been structured for anonymous peer review. All personal identifiers, commit signatures, and institution names have been scrubbed. Permanent DOIs and public repository links will be activated upon publication acceptance.