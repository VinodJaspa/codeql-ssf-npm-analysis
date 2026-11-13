#!/usr/bin/env python3
"""Scan a package corpus (discovered via package.json) with GuardDog.

Output schema is identical to the main evaluation script:
  findings CSV: package,version,label,tool,rule,file,startLine,endLine,message
Plus a summary (manifest) CSV with one row per scanned package, including
packages with zero findings and failed scans. The manifest is the denominator
needed for FPR / recall:
  package,version,label,tool,status,detected,num_findings,error,path,hash

Run from /data/resarch-dataset, e.g.:
  uv run  run_guarddog_scan.py --corpus ../benign_packages --label benign \
      --findings-csv ../results/guarddog__findings_validation-set-benign.csv \
      --summary-csv  ../results/guarddog_summary_validation-set-benign.csv
"""

import argparse
import csv
import hashlib
import json
import multiprocessing as mp
import subprocess
from functools import partial
from pathlib import Path

from tqdm import tqdm

FINDING_FIELDS = [
    "package", "version", "label", "tool",
    "rule", "file", "startLine", "endLine", "message",
]
SUMMARY_FIELDS = [
    "package", "version", "label", "tool", "status",
    "detected", "num_findings", "error", "path", "hash",
]

SKIP_DIRS = {
    "node_modules", ".git", ".hg", ".svn",
    "dist", "build", ".cache", ".next", "coverage",
}




def enumerate_units(corpus: Path, layout="versioned"):
    """Yield (name, version, root). One unit per package-version; no recursion."""
    if not corpus.is_dir():
        raise SystemExit(f"Corpus not found: {corpus}")
    for top in sorted(p for p in corpus.iterdir() if p.is_dir()):
        names = (sorted(c for c in top.iterdir() if c.is_dir())
                 if top.name.startswith("@") else [top])
        for nd in names:
            name = nd.relative_to(corpus).as_posix()
            if layout == "flat":
                yield name, "unknown", nd.resolve()
                continue
            for v in sorted(d for d in nd.iterdir() if d.is_dir()):
                root = v / "package" if (v / "package").is_dir() else v
                yield name, v.name, root.resolve()


def parse_package_id(pkg_path, corpus_dir):
    """Derive (name, version) from the path, handling scoped packages.

    Layout: <corpus>/[@scope/]<name>/<version>/package  ->  ("@scope/name", version)
    """
    parts = list(pkg_path.relative_to(corpus_dir).parts)
    if parts and parts[-1] == "package":
        parts = parts[:-1]
    if len(parts) >= 2:
        return "/".join(parts[:-1]), parts[-1]
    if len(parts) == 1:
        return parts[0], "unknown"
    return str(pkg_path.name), "unknown"


def file_hash(pkg_path):
    """Deterministic SHA-256 over relative paths and contents (skips nested deps)."""
    h = hashlib.sha256()
    for path in sorted(pkg_path.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(pkg_path).as_posix()
            if any(part in SKIP_DIRS for part in Path(rel).parts[:-1]):
                continue
            h.update(rel.encode())
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        except OSError:
            continue
    return h.hexdigest()


def parse_location(location):
    """GuardDog location string -> (file, startLine, endLine)."""
    if not isinstance(location, str) or not location:
        return "", "", ""
    if ":" in location:
        file_path, tail = location.rsplit(":", 1)
        tail = tail.strip()
        try:
            return file_path, int(tail), int(tail)
        except ValueError:
            pass
        if "-" in tail:
            a, _, b = tail.partition("-")
            try:
                return file_path, int(a), int(b)
            except ValueError:
                pass
    return location, "", ""


def extract_findings(name, version, label, data):
    """GuardDog JSON -> rows in the shared findings schema."""
    rows = []
    results = data.get("results", {})
    if not isinstance(results, dict):
        return rows

    for rule, items in results.items():
        if not items:
            continue
        if isinstance(items, (dict, str)):
            items = [items]
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                file_path, start, end = parse_location(item.get("location", ""))
                message = item.get("message", "")
            elif isinstance(item, str):  # metadata rules can return plain strings
                file_path, start, end, message = "", "", "", item
            else:
                continue
            rows.append({
                "package": name, "version": version, "label": label,
                "tool": "guarddog", "rule": rule,
                "file": file_path, "startLine": start, "endLine": end,
                "message": message,
            })
    return rows


def scan_package(pkg_path, corpus_dir, label, guarddog, timeout):
    name, version = parse_package_id(pkg_path, corpus_dir)
    base = {
        "package": name, "version": version, "label": label,
        "tool": "guarddog", "path": str(pkg_path), "hash": file_hash(pkg_path),
    }

    def failed(msg):
        return {**base, "status": "error", "detected": "", "num_findings": "",
                "error": msg[:1000], "findings": []}

    try:
        proc = subprocess.run(
            [guarddog, "npm", "scan", "--output-format", "json", str(pkg_path)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return failed(f"Timed out after {timeout} seconds")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc))

    if proc.returncode != 0 and not proc.stdout.strip():
        return failed(proc.stderr.strip())

    try:
        data = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return failed("Invalid JSON output: " + proc.stderr.strip()[:500])

    findings = extract_findings(name, version, label, data)
    try:
        issues = int(data.get("issues", len(findings)))
    except (TypeError, ValueError):
        issues = len(findings)

    detected = bool(findings) or issues > 0
    return {**base, "status": "ok", "detected": int(detected),
            "num_findings": max(issues, len(findings)), "error": "",
            "findings": findings}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="../npm_dataset")
    ap.add_argument("--label", default="benign", choices=["benign", "malicious"])
    ap.add_argument("--findings-csv", default="../results/guarddog_large_findings.csv")
    ap.add_argument("--summary-csv", default="../results/guarddog_large_summary.csv")
    ap.add_argument("--guarddog", default="/data/guarddog-env/bin/guarddog")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--workers", type=int, default=min(mp.cpu_count(), 8))
    args = ap.parse_args()

    corpus_dir = Path(args.corpus).resolve()
    if not corpus_dir.is_dir():
        raise SystemExit(f"Corpus not found: {corpus_dir}")

    findings_csv, summary_csv = Path(args.findings_csv), Path(args.summary_csv)
    findings_csv.parent.mkdir(parents=True, exist_ok=True)
    summary_csv.parent.mkdir(parents=True, exist_ok=True)

    units = list(enumerate_units(corpus_dir))
    package_dirs = [p for _, _, p in units]
    no_manifest = [p for p in package_dirs if not (p / "package.json").is_file()]
    if no_manifest:
        print(f"WARNING: {len(no_manifest)} units have no package.json, e.g. {no_manifest[:3]}")
        print(f"\nCORPUS: {corpus_dir}\nlabel={args.label}  package dirs={len(package_dirs)}")
        for p in package_dirs[:5]:
            print("  e.g.", parse_package_id(p, corpus_dir), "<-", p.relative_to(corpus_dir))

    worker = partial(scan_package, corpus_dir=corpus_dir, label=args.label,
                     guarddog=args.guarddog, timeout=args.timeout)
    with mp.Pool(args.workers) as pool:
        results = list(tqdm(pool.imap(worker, package_dirs),
                            total=len(package_dirs), desc="GuardDog scan", unit="pkg"))

    with findings_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FINDING_FIELDS)
        w.writeheader()
        for r in results:
            w.writerows(r["findings"])

    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        w.writerows({k: r[k] for k in SUMMARY_FIELDS} for r in results)

    ok = [r for r in results if r["status"] == "ok"]
    failed = len(results) - len(ok)
    flagged = sum(r["detected"] == 1 for r in ok)
    print("\nGUARDDOG SCAN SUMMARY")
    print("=" * 44)
    print(f"Package dirs:       {len(results)}")
    print(f"Successful scans:   {len(ok)}")
    print(f"Failed scans:       {failed}")
    print(f"Flagged:            {flagged}")
    print(f"Not flagged:        {len(ok) - flagged}")
    print(f"Flag rate (ok only): {100 * flagged / len(ok):.2f}%" if ok else "no successful scans")
    print(f"Findings CSV:       {findings_csv}\nSummary CSV:        {summary_csv}")
    if failed:
        print("WARNING: failed scans are neither TP/FP nor TN/FN. Rerun or exclude "
              "them from the denominator and report the count.")


if __name__ == "__main__":
    main()