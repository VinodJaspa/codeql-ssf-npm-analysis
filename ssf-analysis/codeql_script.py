#!/usr/bin/env python3
"""
SSF CodeQL runner .

uv run codeql_script.py
change the PACKAGES_DIRS dict to point to the packages you want to analyze.
The script will create a CodeQL database for each package-version, run all queries in CODEQL_QUERIES_DIR, and save the results to OUTPUT_JSON and OUTPUT_CSV.
The script will cache databases and query results, so rerunning the script will skip packages that have not changed since the last run.
"""
import csv
import glob
import hashlib
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ---------------- Configuration ---------------- #
PACKAGES_DIRS = {
    Path("../training-packages"): "malicious",
    # Path("../benign_packages"): "benign",
}
CODEQL_QUERIES_DIR = Path("../codeql-custom-queries-javascript").resolve()
AUDIT_WORKSPACE = Path("../audit_workspace/codeql").resolve()
LOGS_DIR = Path("codeql-results").resolve()

COMBINED_DIR = LOGS_DIR / "combined_results"
RESULTS_DIR = Path("../results/training-packages-codeql")

OUTPUT_JSON = RESULTS_DIR / "ssf-training-packages-malicious.json"
OUTPUT_CSV = RESULTS_DIR / "ssf_training-packages-malicious.csv"
AUDIT_CSV = RESULTS_DIR / "ssf_training-packages_audit_db_malicious.csv"
TIMING_CSV = RESULTS_DIR / "ssf_training-packages-timing_malicious.csv"

DB_THREADS = 3
MAX_WORKERS = os.cpu_count() or 1
ERROR_TAIL = 1500   # characters of CodeQL output kept in error_message

print(f"[info] Database threads: {DB_THREADS}")
print(f"[info] Concurrent package workers: {MAX_WORKERS}")

AUDIT_WORKSPACE.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
COMBINED_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------- Helpers ---------------- #
def folder_hash(path: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(path.rglob("*")):
        if f.is_file():
            h.update(f.relative_to(path).as_posix().encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has_node_modules(path: Path) -> bool:
    return any(p.is_dir() and p.name == "node_modules" for p in path.rglob("node_modules"))


def tail(text: str, n: int = ERROR_TAIL) -> str:
    text = (text or "").strip()
    return text[-n:]


def enumerate_units(corpus: Path, layout="versioned"):
    """Yield (name, version, root). One unit per package-version."""
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


def rows_from_json(data, pkg, query):
    rows = []
    if "#select" not in data:
        return rows
    columns = [c.get("name", c.get("label", "")) for c in data["#select"].get("columns", [])]
    for t in data["#select"].get("tuples", []):
        row = dict(zip(columns, t))
        rows.append({
            "package": pkg["name"],
            "version": pkg["version"],
            "label": pkg["label"],
            "query": query.stem,
            "file": row.get("filePath") or row.get("file") or row.get("location"),
            "startLine": row.get("startLine"),
            "endLine": row.get("endLine"),
            "message": row.get("message"),
        })
    return rows


# ---------------- Database Creation & Caching ---------------- #
def create_or_skip_db(pkg):
    safe_pkg_name = pkg["name"].replace("/", "__")

    db = AUDIT_WORKSPACE / f"db_{safe_pkg_name}_{pkg['version']}"
    db.parent.mkdir(parents=True, exist_ok=True)
    hash_file = db / ".source_hash"

    audit = {
        "package": pkg["name"],
        "version": pkg["version"],
        "label": pkg["label"],
        "source_type": "npm-tarball",
        "node_modules_present": has_node_modules(pkg["path"]),
        "database_status": None,
        "build_time_seconds": 0.0,
        "query_time_seconds": 0.0,
        "queries_processed": 0,
        "queries_failed": 0,
        "package_time_seconds": 0.0,
        "error_message": "",
    }

    try:
        current_hash = folder_hash(pkg["path"])
        pkg["hash"] = current_hash
    except Exception as e:
        audit["database_status"] = "hash_failed"
        audit["error_message"] = f"Hash failed: {e}"
        print(f"[SKIP] Hash failed for {pkg['name']}@{pkg['version']}: {e}")
        return None, audit

    # Cache hit: source unchanged AND the database looks complete
    if db.exists() and hash_file.exists() and (db / "db-javascript").is_dir():
        try:
            if hash_file.read_text().strip() == current_hash:
                print(f"[SKIP DB] {pkg['name']}@{pkg['version']}")
                audit["database_status"] = "cached"
                return db, audit
        except OSError:
            pass

    print(f"[CREATE DB] {pkg['name']}@{pkg['version']}")
    start_time = time.perf_counter()

    # Hide .d.ts files during extraction, restore afterwards
    dts_files = glob.glob(os.path.join(str(pkg["path"]), "**", "*.d.ts"), recursive=True)
    for f in dts_files:
        if os.path.exists(f):
            try:
                os.rename(f, f + "_bak")
            except Exception as rename_err:
                print(f"[WARN] Failed to hide {f}: {rename_err}")

    env_config = os.environ.copy()
    env_config["CODEQL_EXTRACTOR_JAVASCRIPT_OPTION_NO_BUILD"] = "true"
    env_config["CODEQL_EXTRACTOR_JAVASCRIPT_DISABLE_BUILD"] = "true"

    command = [
        "codeql", 
        "database", 
        "create", 
        str(db), 
        "--language=javascript-typescript",
        f"--source-root={pkg['path']}", 
        "-Oskip_types=true",
        "-Ojavascript.file_extensions=.js,.jsx,.ts,.tsx",
        "--threads", str(DB_THREADS),
        "--overwrite"
    ]
    
    print("Running CodeQL:", " ".join(command), flush=True)

    try:
        # Explicitly set cwd to the package directory to align execution pathing
        proc = subprocess.run(
            command, 
            env=env_config, 
            cwd=pkg['path'], 
            capture_output=True, 
            text=True, 
            check=False,
        )
        
        # Highly recommended: Check if the command actually succeeded
        if proc.returncode != 0:
            print(f"CodeQL Failed (Exit Code {proc.returncode})", flush=True)
            print(f"STDOUT:\n{proc.stdout}", flush=True)
            print(f"STDERR:\n{proc.stderr}", flush=True)
        else:
            print("CodeQL database created successfully!", flush=True)
        audit["build_time_seconds"] = round(time.perf_counter() - start_time, 3)

        if proc.returncode != 0 or not (db / "db-javascript").is_dir():
            # Never cache a failed database
            if hash_file.exists():
                hash_file.unlink()
            msg = (proc.stdout or "") + "\n" + (proc.stderr or "")
            print(f"[CODEQL ERROR] Failed DB for {pkg['name']}@{pkg['version']} "
                  f"(exit {proc.returncode})")
            audit["database_status"] = "failed"
            audit["error_message"] = tail(msg)
            return None, audit

        hash_file.write_text(current_hash)
        audit["database_status"] = "success"
        return db, audit

    except Exception as e:
        print(f"[CODEQL ERROR] {pkg['name']}@{pkg['version']}: {e}")
        audit["database_status"] = "failed"
        audit["build_time_seconds"] = round(time.perf_counter() - start_time, 3)
        audit["error_message"] = str(e)
        return None, audit

    finally:
        for f in dts_files:
            bak_file = f + "_bak"
            if os.path.exists(bak_file):
                try:
                    os.rename(bak_file, f)
                except Exception as restore_err:
                    print(f"[WARN] Failed to restore {f}: {restore_err}")


# ---------------- Query Execution with Caching ---------------- #
def run_query(pkg, db, query):
    """Return (results, error). error == "" means the query really ran."""
    safe = pkg["name"].replace("/", "__")
    log_dir = LOGS_DIR / query.stem / f"{safe}_{pkg['version']}"
    log_dir.mkdir(parents=True, exist_ok=True)

    bqrs = log_dir / f"{query.stem}.bqrs"
    json_out = log_dir / f"{query.stem}.json"
    meta = log_dir / f"{query.stem}.meta.json"

    pkg_hash = pkg.get("hash") or folder_hash(pkg["path"])
    query_hash = file_hash(query)

    # Cache hit
    if meta.exists() and json_out.exists() and json_out.stat().st_size > 0:
        try:
            md = json.loads(meta.read_text())
            if md.get("pkg_hash") == pkg_hash and md.get("query_hash") == query_hash:
                print(f"[CACHE HIT] {pkg['name']}@{pkg['version']} | {query.stem}")
                return rows_from_json(json.loads(json_out.read_text()), pkg, query), ""
        except Exception:
            pass

    print(f"[RUN QUERY] {pkg['name']}@{pkg['version']} | {query.stem}")

    # Remove stale outputs so a failure cannot be mistaken for a result
    for p in (bqrs, json_out, meta):
        if p.exists():
            p.unlink()

    try:
        r = subprocess.run(["codeql", "query", "run", str(query), "--database", str(db),
                            "--output", str(bqrs)],
                           capture_output=True, text=True, check=False)
        if r.returncode != 0 or not bqrs.exists():
            err = f"query run exit {r.returncode}: {tail(r.stderr or r.stdout)}"
            (log_dir / f"{query.stem}.error.txt").write_text(err)
            print(f"[ERROR] {pkg['name']}@{pkg['version']} | {query.stem}: {err[:300]}")
            return [], err

        d = subprocess.run(["codeql", "bqrs", "decode", str(bqrs), "--format=json",
                            "--output", str(json_out)],
                           capture_output=True, text=True, check=False)
        if d.returncode != 0 or not json_out.exists():
            err = f"bqrs decode exit {d.returncode}: {tail(d.stderr or d.stdout)}"
            (log_dir / f"{query.stem}.error.txt").write_text(err)
            print(f"[ERROR] {pkg['name']}@{pkg['version']} | {query.stem}: {err[:300]}")
            return [], err

        meta.write_text(json.dumps({"pkg_hash": pkg_hash, "query_hash": query_hash}, indent=2))
        return rows_from_json(json.loads(json_out.read_text()), pkg, query), ""

    except Exception as e:
        print(f"[ERROR] {pkg['name']}@{pkg['version']} | {query.stem}: {e}")
        return [], str(e)


# ---------------- Package Processing & Timing ---------------- #
def process_package(pkg, queries):
    package_start = time.perf_counter()
    query_time_total = 0.0
    queries_processed = 0
    errors = []

    db, audit = create_or_skip_db(pkg)

    if db is None:
        audit["package_time_seconds"] = round(time.perf_counter() - package_start, 3)
        return [], audit

    results = []
    for query in queries:
        query_start = time.perf_counter()
        query_results, err = run_query(pkg, db, query)
        query_time_total += time.perf_counter() - query_start
        if err:
            errors.append(f"{query.stem}: {err}")
        else:
            queries_processed += 1
            results.extend(query_results)

    audit["query_time_seconds"] = round(query_time_total, 3)
    audit["queries_processed"] = queries_processed
    audit["queries_failed"] = len(errors)
    if errors:
        # analysis is incomplete: do not let the evaluation count this package as analyzed
        audit["database_status"] = "query_failed"
        audit["error_message"] = tail(" | ".join(errors), 2000)
    audit["package_time_seconds"] = round(time.perf_counter() - package_start, 3)
    return results, audit


def result_key(r):
    return (r["package"], r["version"], r["query"], r["file"], r["startLine"], r["endLine"])


# ---------------- Main Runner ---------------- #
def run_codeql():
    run_start = time.perf_counter()

    queries = sorted(CODEQL_QUERIES_DIR.glob("*.ql"))
    packages = []
    for base, label in PACKAGES_DIRS.items():
        for name, version, path in enumerate_units(base):
            packages.append({"name": name, "version": version, "path": path, "label": label})

    print(f"[INFO] Total package versions: {len(packages)}")
    print(f"[INFO] CodeQL queries: {len(queries)}")

    all_results, all_audits = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for results, audit in executor.map(lambda p: process_package(p, queries), packages):
            all_results.extend(results)
            all_audits.append(audit)

    merged_results = list({result_key(r): r for r in all_results}.values())
    OUTPUT_JSON.write_text(json.dumps(merged_results, indent=2))

    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["package", "version", "label", "query",
                                               "file", "startLine", "endLine", "message"])
        writer.writeheader()
        writer.writerows(merged_results)

    audit_fields = ["package", "version", "label", "source_type", "node_modules_present",
                    "database_status", "build_time_seconds", "query_time_seconds",
                    "queries_processed", "queries_failed", "package_time_seconds",
                    "error_message"]
    with AUDIT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=audit_fields)
        writer.writeheader()
        writer.writerows(all_audits)

    total_elapsed = time.perf_counter() - run_start

    def count(status):
        return sum(a["database_status"] == status for a in all_audits)

    total = len(all_audits)
    fresh_db, cached_db = count("success"), count("cached")
    failed, hash_failed, query_failed = count("failed"), count("hash_failed"), count("query_failed")
    success = fresh_db + cached_db
    node_modules_count = sum(a["node_modules_present"] for a in all_audits)

    package_times = [a["package_time_seconds"] for a in all_audits
                     if a.get("package_time_seconds") is not None]
    db_times = [a["build_time_seconds"] for a in all_audits if a["database_status"] == "success"]
    query_times = [a["query_time_seconds"] for a in all_audits
                   if a.get("query_time_seconds") is not None]
    avg_package = sum(package_times) / len(package_times) if package_times else 0
    avg_db = sum(db_times) / len(db_times) if db_times else 0
    avg_query = sum(query_times) / len(query_times) if query_times else 0

    with TIMING_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "package_versions", "database_success_or_cached", "fresh_databases_built",
            "cached_databases", "database_failures", "query_failures", "hash_failures",
            "wall_clock_seconds", "wall_clock_minutes", "average_package_seconds",
            "average_fresh_database_build_seconds", "average_query_processing_seconds",
            "sum_package_processing_seconds", "codeql_queries_per_package",
            "max_workers", "database_threads"])
        writer.writeheader()
        writer.writerow({
            "package_versions": total, "database_success_or_cached": success,
            "fresh_databases_built": fresh_db, "cached_databases": cached_db,
            "database_failures": failed, "query_failures": query_failed,
            "hash_failures": hash_failed,
            "wall_clock_seconds": round(total_elapsed, 3),
            "wall_clock_minutes": round(total_elapsed / 60, 3),
            "average_package_seconds": round(avg_package, 3),
            "average_fresh_database_build_seconds": round(avg_db, 3),
            "average_query_processing_seconds": round(avg_query, 3),
            "sum_package_processing_seconds": round(sum(package_times), 3),
            "codeql_queries_per_package": len(queries),
            "max_workers": MAX_WORKERS, "database_threads": DB_THREADS})

    print()
    print("=" * 64)
    print("CODEQL DATABASE AUDIT SUMMARY")
    print("=" * 64)
    print(f"Total package versions       : {total}")
    print(f"Database success or cached   : {success}")
    print(f"Fresh databases built        : {fresh_db}")
    print(f"Cached databases reused      : {cached_db}")
    print(f"Database failures            : {failed}")
    print(f"Query-stage failures         : {query_failed}   (DB built, >= 1 query did not run)")
    print(f"Hash failures                : {hash_failed}")
    print(f"node_modules present         : {node_modules_count}")
    print("-" * 64)
    print("RUNTIME SUMMARY")
    print("-" * 64)
    print(f"Total wall-clock time        : {total_elapsed:.2f} seconds ({total_elapsed / 60:.2f} min)")
    print(f"Average time per package     : {avg_package:.2f} seconds")
    print(f"Average fresh DB build time  : {avg_db:.2f} seconds")
    print(f"Average query processing     : {avg_query:.2f} seconds")
    print(f"Sum of package processing    : {sum(package_times):.2f} seconds")
    print(f"Concurrent workers           : {MAX_WORKERS}")
    print(f"Threads per database         : {DB_THREADS}")
    print("=" * 64)
    if query_failed:
        print(f"[WARN] {query_failed} package(s) had failing queries; see error_message in {AUDIT_CSV}")
    print(f"[DONE] JSON    -> {OUTPUT_JSON}")
    print(f"[DONE] CSV     -> {OUTPUT_CSV}")
    print(f"[DONE] Audit   -> {AUDIT_CSV}")
    print(f"[DONE] Timing  -> {TIMING_CSV}")


if __name__ == "__main__":
    run_codeql()