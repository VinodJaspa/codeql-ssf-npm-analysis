#!/usr/bin/env python3
"""
cd Backstabbers-Knife-Collection
git lfs install
git lfs pull

uv run --python 3.12 --with zstandard --with requests collect_bkc.py \
   --repo Backstabbers-Knife-Collection --names test-packages-names.txt --out training-packages

names file: "<name><TAB/space><name-version.tgz>" per line (2nd column optional).
Source: local BKC clone; LFS tarballs are fetched from the BKC repo's own LFS endpoint.
Extract only; nothing is executed. Run in a VM/container.
"""
import argparse, hashlib, io, json, re, shutil, tarfile
from pathlib import Path
import requests, zstandard

ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True)
ap.add_argument("--names", required=True)
ap.add_argument("--out", default="training-packages")
a = ap.parse_args()

repo = Path(a.repo).resolve()
base = repo / "samples" / "npm"
out = Path(a.out); out.mkdir(exist_ok=True)
FN = re.compile(r"^(.+)-(\d+\.\d+\.\d+(?:[-+].*)?)\.tgz$")
LFS_API = "https://github.com/cybertier/Backstabbers-Knife-Collection.git/info/lfs/objects/batch"
HDR = {"Accept": "application/vnd.git-lfs+json", "Content-Type": "application/vnd.git-lfs+json"}

# ---------- parse names ----------
entries = []
for line in open(a.names):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    p = line.split()
    if len(p) > 1 and (m := FN.match(p[1])):
        entries.append((m.group(1), m.group(2), line))
    else:
        entries.append((p[0], None, line))


# ---------- helpers ----------
def is_lfs(path):
    with open(path, "rb") as f:
        return f.read(40).startswith(b"version https://git-lfs")


def open_tar(data: bytes):
    if data[:4] == b"\x28\xb5\x2f\xfd":                      # zstd-wrapped tar
        data = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    return tarfile.open(fileobj=io.BytesIO(data), mode="r:*")


def safe_extract(t, dest: Path):
    d = dest.resolve()
    for m in t.getmembers():
        if not (m.isfile() or m.isdir()):
            continue                                          # skip symlinks/devices
        rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
        if not rel:
            continue
        p = (dest / rel).resolve()
        if d not in p.parents and p != d:
            continue                                          # block path traversal
        if m.isdir():
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            with t.extractfile(m) as s, open(p, "wb") as o:
                shutil.copyfileobj(s, o)


def install(tgz: Path, dest: Path):
    dest.mkdir(parents=True)
    try:
        with open_tar(tgz.read_bytes()) as t:
            safe_extract(t, dest)
        meta = tgz.parent / "meta.json.zst"
        if meta.exists() and not is_lfs(meta):
            shutil.copy2(meta, dest / "_bkc_meta.json.zst")
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise


def parse_pointer(p):
    t = p.read_text(errors="replace")
    return (re.search(r"oid sha256:([0-9a-f]{64})", t).group(1),
            int(re.search(r"size (\d+)", t).group(1)))


# ---------- index BKC ----------
by_file = {}
for p in base.rglob("*.tgz"):
    by_file.setdefault(p.name, []).append(p)


def candidates(name, ver):
    if ver:
        c = list(by_file.get(f"{name}-{ver}.tgz", []))
        if not c and (base / name / ver).is_dir():
            c = list((base / name / ver).glob("*.tgz"))
        return c
    d = base / name
    return list(d.rglob("*.tgz")) if d.is_dir() else []


plan = {raw: candidates(n, v) for n, v, raw in entries}

# ---------- fetch LFS objects for matched pointers only ----------
pointers = sorted({p for hits in plan.values() for p in hits if is_lfs(p)})
print(f"{len(pointers)} LFS pointers to fetch", flush=True)
for i in range(0, len(pointers), 50):
    chunk = pointers[i:i + 50]
    info = {p: parse_pointer(p) for p in chunk}
    body = {"operation": "download", "transfers": ["basic"],
            "objects": [{"oid": o, "size": s} for o, s in info.values()]}
    try:
        r = requests.post(LFS_API, data=json.dumps(body), headers=HDR, timeout=60)
        r.raise_for_status()
    except Exception as e:
        print(f"  batch request failed: {e}", flush=True)
        continue
    objs = {o["oid"]: o for o in r.json().get("objects", [])}
    for p, (oid, size) in info.items():
        tag = f"{p.parent.parent.name}@{p.parent.name}"
        act = objs.get(oid, {}).get("actions", {}).get("download")
        if not act:
            print(f"  no download for {tag}: {objs.get(oid, {}).get('error')}", flush=True)
            continue
        try:
            d = requests.get(act["href"], headers=act.get("header", {}), timeout=(15, 120))
            d.raise_for_status()
            if hashlib.sha256(d.content).hexdigest() != oid:
                print(f"  hash mismatch {tag}", flush=True); continue
            p.write_bytes(d.content)
            print(f"  fetched {tag} ({size} bytes)", flush=True)
        except Exception as e:
            print(f"  fetch failed {tag}: {e}", flush=True)

# ---------- install ----------
ok, unresolved = [], []
for name, ver, raw in entries:
    print(name, flush=True)
    done, reason = False, ""
    for tgz in plan[raw]:
        if is_lfs(tgz):
            reason = "still a Git LFS pointer (fetch failed)"
            continue
        pkg = tgz.parent.parent.relative_to(base)
        dest = out / pkg / tgz.parent.name
        if dest.exists():
            done = True
            continue
        try:
            install(tgz, dest)
            print(f"  ok {pkg}@{tgz.parent.name}")
            done = True
        except Exception as e:
            reason = f"extract error: {e}"
    if done:
        ok.append(raw)
        continue
    if not plan[raw]:
        d = base / name
        have = sorted(x.name for x in d.iterdir() if x.is_dir()) if d.is_dir() else []
        reason = (f"BKC has {name} only as versions {have}, not {ver}" if have else "not in BKC")
    unresolved.append(f"{name}\t{ver}\t{reason}")
    print(f"  [unresolved] {name}@{ver}: {reason}")

Path("unresolved.txt").write_text("\n".join(unresolved) + "\n")
print(f"\nCollected {len(ok)}/{len(entries)}. Unresolved {len(unresolved)} -> unresolved.txt")