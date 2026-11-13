#!/usr/bin/env python3
"""
Second benign corpus: npm packages that legitimately do I/O (CLIs, SDKs, API clients, build tools).
This is for Stress test for SSF and GuardDog, to see if they flag benign packages that legitimately do I/O.
Run:  uv run download_io_benign.py
Needs: requests, tqdm, packaging
"""
import csv
import os
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests
from packaging.version import Version, InvalidVersion
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry

# ----------------------------------------------------------------- config
BASE_DIR = "../npm_dataset_io"
EXISTING_CORPUS = "../benign_packages"          # packages already in the first benign set are excluded
KEYWORDS = ["cli", "sdk", "api-client", "build-tool"]
PER_KEYWORD_CANDIDATES = 400             # raw candidates pulled per keyword
TARGET_PER_KEYWORD = 100                 # kept per keyword after the download filter
MIN_DOWNLOADS = 5000                     # same threshold as the first benign set
MAX_WORKERS = 12
TIMEOUT = 30

SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
REGISTRY_URL = "https://registry.npmjs.org/"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-month/"
INSTALL_HOOKS = ("preinstall", "install", "postinstall")

_local = threading.local()


def session():
    if not hasattr(_local, "s"):
        s = requests.Session()
        retry = Retry(total=4, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        ad = HTTPAdapter(max_retries=retry, pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS * 2)
        s.mount("https://", ad)
        _local.s = s
    return _local.s


# ----------------------------------------------------------------- discovery
def search_keyword(kw):
    """Names for one keyword, via the npm registry search (max 250 per page)."""
    names, offset = [], 0
    while len(names) < PER_KEYWORD_CANDIDATES:
        try:
            r = session().get(SEARCH_URL, params={"text": f"keywords:{kw}", "size": 250, "from": offset},
                              timeout=TIMEOUT)
            r.raise_for_status()
            objs = r.json().get("objects", [])
        except Exception as e:
            print(f"[search error] {kw} offset={offset}: {e}")
            break
        if not objs:
            break
        names += [o["package"]["name"] for o in objs]
        offset += 250
    return names[:PER_KEYWORD_CANDIDATES]


def existing_names():
    out = set()
    if not os.path.isdir(EXISTING_CORPUS):
        return out
    for top in os.listdir(EXISTING_CORPUS):
        p = os.path.join(EXISTING_CORPUS, top)
        if not os.path.isdir(p):
            continue
        if top.startswith("@"):
            out |= {f"{top}/{c}" for c in os.listdir(p)}
        else:
            out.add(top)
    return out


# ----------------------------------------------------------------- per-package work
def check_downloads(name):
    """Returns (downloads or None, error string). An error is NOT treated as 'below threshold'."""
    try:
        r = session().get(DOWNLOADS_URL + name, timeout=TIMEOUT)
        if r.status_code != 200:
            return None, f"http {r.status_code}"
        return int(r.json().get("downloads", 0)), ""
    except Exception as e:
        return None, str(e)[:200]


def pick_version(name):
    """Highest stable semver. Returns (version, tarball, has_install_script, error)."""
    try:
        r = session().get(REGISTRY_URL + quote(name, safe="@"), timeout=TIMEOUT)
        r.raise_for_status()
        versions = r.json().get("versions", {})
    except Exception as e:
        return None, None, None, f"registry: {str(e)[:200]}"
    best = None
    for v in versions:
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv.is_prerelease or pv.is_devrelease:
            continue
        if best is None or pv > best[0]:
            best = (pv, v)
    if best is None:
        return None, None, None, "no stable version"
    meta = versions[best[1]]
    scripts = meta.get("scripts") or {}
    has_hook = any(h in scripts for h in INSTALL_HOOKS)
    return best[1], meta["dist"]["tarball"], has_hook, ""


def safe_extract(tar, path):
    if hasattr(tarfile, "data_filter"):               # Python 3.12+ (and backports)
        tar.extractall(path=path, filter="data")
        return
    base = os.path.realpath(path)
    for m in tar.getmembers():                         # manual path-traversal / link guard
        target = os.path.realpath(os.path.join(path, m.name))
        if not target.startswith(base + os.sep) and target != base:
            raise ValueError(f"unsafe path in tarball: {m.name}")
        if m.issym() or m.islnk():
            continue
    tar.extractall(path=path, members=[m for m in tar.getmembers() if not (m.issym() or m.islnk())])


def download(name, version, tarball):
    pkg_dir = os.path.join(BASE_DIR, name, version)
    if os.path.isdir(os.path.join(pkg_dir, "package")):
        return "cached", ""
    os.makedirs(pkg_dir, exist_ok=True)
    tgz = os.path.join(pkg_dir, "package.tgz")
    try:
        with session().get(tarball, stream=True, timeout=TIMEOUT) as r:
            r.raise_for_status()
            with open(tgz, "wb") as f:
                for chunk in r.iter_content(1024 * 1024):
                    f.write(chunk)
        with tarfile.open(tgz, "r:gz") as tar:
            safe_extract(tar, pkg_dir)
        return "downloaded", ""
    except Exception as e:
        return "failed", str(e)[:200]
    finally:
        if os.path.exists(tgz):
            os.remove(tgz)


def process(name, kw):
    row = {"name": name, "keyword": kw, "downloads": "", "version": "", "has_install_script": "",
           "status": "", "reason": ""}
    d, err = check_downloads(name)
    if d is None:
        row.update(status="dropped", reason=f"downloads lookup failed: {err}")
        return row
    row["downloads"] = d
    if d < MIN_DOWNLOADS:
        row.update(status="dropped", reason="below download threshold")
        return row
    ver, tar_url, hook, err = pick_version(name)
    if ver is None:
        row.update(status="dropped", reason=err)
        return row
    row.update(version=ver, has_install_script=int(hook))
    status, err = download(name, ver, tar_url)
    row.update(status=status, reason=err)
    return row


# ----------------------------------------------------------------- main
def main():
    os.makedirs(BASE_DIR, exist_ok=True)
    skip = existing_names()
    print(f"Excluding {len(skip)} names already in {EXISTING_CORPUS}")

    seen, work = set(skip), []
    for kw in KEYWORDS:
        cands = search_keyword(kw)
        fresh = [n for n in cands if n not in seen]
        seen |= set(fresh)
        print(f"{kw}: {len(cands)} candidates, {len(fresh)} new")
        work += [(n, kw) for n in fresh]

    rows = []
    kept = {kw: 0 for kw in KEYWORDS}
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futs = {ex.submit(process, n, kw): kw for n, kw in work}
        for f in tqdm(as_completed(futs), total=len(futs), desc="Processing"):
            row = f.result()
            kw = row["keyword"]
            if row["status"] in ("downloaded", "cached"):
                if kept[kw] >= TARGET_PER_KEYWORD:
                    row["status"] = "surplus"        # downloaded but over the per-keyword cap
                else:
                    kept[kw] += 1
            rows.append(row)

    with open(os.path.join(BASE_DIR, "candidates_log.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: r["name"]))

    ok = [r for r in rows if r["status"] in ("downloaded", "cached")]
    print("\n=== SUMMARY (put these numbers in the methods) ===")
    print(f"candidates (after exclusion): {len(rows)}")
    for s in ("downloaded", "cached", "surplus", "failed", "dropped"):
        print(f"  {s:<11}: {sum(r['status'] == s for r in rows)}")
    print(f"kept per keyword: {kept}")
    print(f"kept with install script: {sum(r['has_install_script'] == 1 for r in ok)}")
    print(f"log: {BASE_DIR}/candidates_log.csv")


if __name__ == "__main__":
    main()