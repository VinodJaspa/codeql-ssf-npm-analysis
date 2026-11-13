#!/usr/bin/env python3
"""
API-category extractor v3 for the SSF statistical analysis.

Usage:
  uv run extract_api_counts.py --selftest            # run this FIRST
  uv run extract_api_counts.py --dataset ../npm_dataset_io   --label benign    --out benign
  uv run extract_api_counts.py --dataset ../temporal_corups --label malicious --out malicious

What v3 fixes relative to the edited v2 you ran:
  1. ast_nodes is the TRUE node count again (full traversal). The query-based version
     set ast_nodes = number of call/new expressions, which silently changed the size
     covariate used in every regression.
  2. No tree-sitter Query API (its return type differs across py-tree-sitter versions
     and the failure was swallowed). Plain traversal, same semantics as before.
  3. Alias regexes are anchored at a word boundary: (?<![\\w$]). The loosened
     `(\\w+)\\s*=\\s*...require(` from v2 was quadratic on very long identifier-like
     runs (hex/base64 blobs) and is the most likely cause of the hang.
  4. Files are NOT skipped for "minified" by default (that drops exactly the
     obfuscated files category E is about). Opt in with --skip-long-line N; every skip
     is counted in the CSV.
  5. Breadcrumbs: each worker writes the file it is analysing to .crumb_<pid>, so a
     hang can be located with `cat .crumb_*`.
  6. imap_unordered(chunksize=1) so one slow unit cannot hold others in its chunk;
     progress printed every 25 units.
  7. Every counter (skips, errors) is written to the CSV; nothing is dropped silently.

Category definitions are unchanged. `total_call_expressions` counts call AND new
expressions. Still approximate: name-based / regex alias resolution, no data flow,
no computed or obfuscated member calls, HTTP lexicon = fetch / XMLHttpRequest /
axios / http(s).
"""
import argparse, csv, glob, logging, os, re, sys, tempfile, time
from collections import defaultdict
from multiprocessing import Pool, cpu_count
import json
import os
from tree_sitter import Language, Parser
import tree_sitter_javascript as ts_js
try:
    import tree_sitter_typescript as ts_ts
except ImportError:
    ts_ts = None

CATS = ["OS & File System", "Process Execution", "Network & HTTP",
        "Serialization & Buffer", "Encoding & Obfuscation"]
SRC_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
EXCLUDE_DIRS = {"node_modules", ".git"}
MODULES = {"fs", "os", "child_process", "http", "https"}
MODS = "|".join(sorted(MODULES))
SEMVER = re.compile(r"^v?\d+(\.\d+){0,3}([-+.][0-9A-Za-z.\-+]*)?$")

# (?<![\w$]) anchors each attempt at the start of an identifier, which keeps matching
# linear on long \w runs. The optional (?:\w+\(\s*)? tolerates one interop wrapper
# such as __importStar(...), __importDefault(...), __toESM(..., 1).
REQ_ASSIGN = re.compile(
    r"(?<![\w$])(\w+)\s*=\s*(?:\w+\(\s*)?require\(\s*['\"](?:node:)?(%s)(?:/promises)?['\"]\s*\)" % MODS)
REQ_DESTR = re.compile(
    r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:\w+\(\s*)?require\(\s*['\"](?:node:)?(%s)(?:/promises)?['\"]\s*\)" % MODS)
IMP_DEFAULT = re.compile(
    r"import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+['\"](?:node:)?(%s)(?:/promises)?['\"]" % MODS)
IMP_NAMED = re.compile(
    r"import\s*\{([^}]+)\}\s*from\s*['\"](?:node:)?(%s)(?:/promises)?['\"]" % MODS)
INLINE_REQ = re.compile(r"^require\(\s*['\"](?:node:)?(%s)(?:/promises)?['\"]\s*\)\." % MODS)


# ------------------------------------------------------------------ parsers
def make_parsers():
    p = {"js": Parser(Language(ts_js.language()))}
    if ts_ts:
        p["ts"] = Parser(Language(ts_ts.language_typescript()))
        p["tsx"] = Parser(Language(ts_ts.language_tsx()))
    return p

_PARSERS = None
def parser_for(path):
    global _PARSERS
    if _PARSERS is None:
        _PARSERS = make_parsers()
    if path.endswith(".tsx") and "tsx" in _PARSERS:
        return _PARSERS["tsx"], False
    if path.endswith(".ts") and "ts" in _PARSERS:
        return _PARSERS["ts"], False
    return _PARSERS["js"], path.endswith((".ts", ".tsx"))  # True = TS parsed as JS (fallback)


# ------------------------------------------------------------------ aliasing
def build_alias_map(code):
    """local name -> 'module' (whole module) or 'module.member' (destructured member)."""
    amap = {}
    for m in REQ_ASSIGN.finditer(code):
        amap[m.group(1)] = m.group(2)
    for m in IMP_DEFAULT.finditer(code):
        amap[m.group(1)] = m.group(2)
    for rx in (REQ_DESTR, IMP_NAMED):
        for m in rx.finditer(code):
            for part in m.group(1).split(","):
                part = part.strip()
                if not part:
                    continue
                bits = re.split(r"\s+as\s+|\s*:\s*", part)
                orig = bits[0].strip()
                local = bits[-1].strip()
                if orig and local:
                    amap[local] = f"{m.group(2)}.{orig}"
    return amap


def normalise(name, amap, use_alias):
    name = name.strip()
    if not use_alias:
        return name
    m = INLINE_REQ.match(name)
    if m:
        return m.group(1) + "." + name[m.end():]
    if not amap:
        return name
    head, dot, rest = name.partition(".")
    if head in amap:
        return amap[head] + (dot + rest if dot else "")
    return name


# ------------------------------------------------------------------ categories
PROC_BARE = {"eval", "Function"}

def categorize(name):
    n = name
    if n.startswith(("os.", "fs.")):
        return "OS & File System"
    if n.startswith("child_process.") or n in PROC_BARE:
        return "Process Execution"
    if n in ("fetch", "XMLHttpRequest", "axios") or n.startswith(("http.", "https.", "axios.")):
        return "Network & HTTP"
    if n == "Buffer" or n.startswith("Buffer.") or n in ("JSON.parse", "JSON.stringify", "unserialize"):
        return "Serialization & Buffer"
    if n in ("encodeURIComponent", "decodeURIComponent", "btoa", "atob", "escape", "unescape"):
        return "Encoding & Obfuscation"
    return None


# ------------------------------------------------------------------ one file
def analyze_file(path, use_alias, max_bytes, skip_long_line=0):
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return {"skipped_large": 1}
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        logging.warning("read error %s: %s", path, e)
        return {"read_error": 1}

    if skip_long_line and code and max(map(len, code.splitlines() or [""])) > skip_long_line:
        return {"skipped_minified": 1}

    out = {c: 0 for c in CATS}
    out.update(total_call_expressions=0, code_bytes=len(code.encode("utf-8")),
               code_lines=code.count("\n") + 1, ast_nodes=0)
    if not code.strip():
        out["parse_success"] = 1
        return out

    parser, ts_fallback = parser_for(path)
    data = code.encode("utf-8")
    tree = parser.parse(data)
    amap = build_alias_map(code) if (use_alias and ("require" in code or "import" in code)) else {}
    if ts_fallback:
        out["ts_parsed_as_js"] = 1
    if tree.root_node.has_error:
        out["syntax_error_files"] = 1
    out["parse_success"] = 1

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        out["ast_nodes"] += 1                      # TRUE node count (all nodes)
        t = node.type
        if t == "call_expression" or t == "new_expression":
            out["total_call_expressions"] += 1
            fn = node.child_by_field_name("function" if t == "call_expression" else "constructor")
            if fn is not None:
                raw = data[fn.start_byte:fn.end_byte].decode("utf-8", errors="ignore")
                cat = categorize(normalise(raw, amap, use_alias))
                if cat:
                    out[cat] += 1
        stack.extend(node.children)
    return out


# ------------------------------------------------------------------ layout
def list_dirs(p):
    return [d for d in sorted(os.listdir(p)) if os.path.isdir(os.path.join(p, d))]

def classify_package(pkg_path, forced):
    if forced != "auto":
        return forced, "forced"
    subs = [d for d in list_dirs(pkg_path) if d not in EXCLUDE_DIRS]
    if os.path.isfile(os.path.join(pkg_path, "package.json")):
        return "flat", "package.json at root"
    if subs and all(SEMVER.match(d) for d in subs):
        return "versioned", "all subfolders semver"
    if subs and all(os.path.isfile(os.path.join(pkg_path, d, "package.json")) or
                    os.path.isdir(os.path.join(pkg_path, d, "package")) for d in subs):
        return "versioned", "each subfolder holds a package"
    return "flat", "ambiguous -> treated flat (CHECK)"



def enumerate_units(dataset, forced):
    """yield (pkg_name, version_or_None, path, layout, reason)"""

    for top in sorted(os.listdir(dataset)):
        tp = os.path.join(dataset, top)

        if not os.path.isdir(tp):
            continue

        children = [(top, tp)]

        if top.startswith("@"):
            children = [
                (f"{top}/{c}", os.path.join(tp, c))
                for c in list_dirs(tp)
            ]

        for name, p in children:
            layout, why = classify_package(p, forced)

            if layout == "versioned":
                for v in list_dirs(p):
                    if v in EXCLUDE_DIRS:
                        continue

                    package_path = os.path.join(p, v)
                    pkg_json = os.path.join(package_path, "package.json")

                    pkg_name, version = name, v

                    if os.path.isfile(pkg_json):
                        try:
                            with open(pkg_json, encoding="utf-8") as f:
                                metadata = json.load(f)

                            pkg_name = metadata.get("name") or name
                            version = metadata.get("version") or v

                        except (json.JSONDecodeError, OSError):
                            pass

                    yield pkg_name, version, package_path, layout, why

            else:
                pkg_json = os.path.join(p, "package.json")
                pkg_name, version = name, None

                if os.path.isfile(pkg_json):
                    try:
                        with open(pkg_json, encoding="utf-8") as f:
                            metadata = json.load(f)

                        pkg_name = metadata.get("name") or name
                        version = metadata.get("version") or None

                    except (json.JSONDecodeError, OSError):
                        pass

                yield pkg_name, version, p, layout, why


# ------------------------------------------------------------------ one unit
def _crumb(text):
    try:
        with open(f".crumb_{os.getpid()}", "w") as fh:
            fh.write(text)
    except Exception:
        pass

def process_unit(args):
    name, version, path, layout, why, use_alias, include_nm, max_bytes, skip_long = args
    res = defaultdict(int)
    try:
        for root, dirs, files in os.walk(path):
            if not include_nm:
                for d in [d for d in dirs if d in EXCLUDE_DIRS]:
                    for _, _, fs_ in os.walk(os.path.join(root, d)):
                        res["vendored_files_skipped"] += sum(1 for x in fs_ if x.endswith(SRC_EXT))
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in files:
                if not f.endswith(SRC_EXT) or f.endswith(".d.ts"):
                    continue
                fp = os.path.join(root, f)
                _crumb(fp)
                try:
                    r = analyze_file(fp, use_alias, max_bytes, skip_long)
                except Exception as exc:
                    logging.error("file error %s: %s", fp, exc)
                    r = {"file_error": 1}
                res["file_count"] += 1
                for k, v in r.items():
                    res[k] += v
    except Exception as exc:
        res["worker_error"] = 1
        logging.error("unit error %s %s: %s", name, version, exc)

    safe = name.replace("/", "__")
    pid = f"{safe}_v{version}" if version else safe
    res["analyzable"] = int(res["parse_success"] > 0 and res["total_call_expressions"] > 0)
    return pid, name, version, layout, why, dict(res)


# ------------------------------------------------------------------ selftest
def run_selftest():
    A, B, C, D, E = CATS
    cases = [
        ("new Function('x');",                                         {B: 1}),
        ("new XMLHttpRequest();",                                      {C: 1}),
        ("new Buffer('abc');",                                         {D: 1}),
        ("const fs_1 = __importStar(require('fs')); fs_1.readFileSync('a');", {A: 1}),
        ("const fs_1 = __importDefault(require('fs')); fs_1.default.readFileSync('a');", {A: 1}),
        ("var a=require('fs'),b=require('child_process'); a.readFileSync('x'); b.exec('y');",
                                                                       {A: 1, B: 1}),
        ("const p = require('fs/promises'); p.readFile('x');",         {A: 1}),
        ("const {exec} = require('node:child_process'); exec('ls');",  {B: 1}),
        ("import fs from 'node:fs'; fs.writeFileSync('a','b');",       {A: 1}),
        ("setTimeout(function(){}, 1);",                               {}),
        ("/x/.exec('a');",                                             {}),
        ("encodeURIComponent('a'); btoa('b');",                        {E: 2}),
    ]
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        for i, (src, expected) in enumerate(cases):
            p = os.path.join(tmp, f"case{i}.js")
            with open(p, "w") as f:
                f.write(src)
            r = analyze_file(p, True, 10 * 1024 * 1024)
            got = {c: r.get(c, 0) for c in CATS}
            want = {c: expected.get(c, 0) for c in CATS}
            good = got == want
            ok &= good
            print(f"[{'PASS' if good else 'FAIL'}] {src}")
            if not good:
                print(f"        expected {expected}  got { {k: v for k, v in got.items() if v} }")

        # ast_nodes must be the full node count, not the number of calls
        p = os.path.join(tmp, "nodes.js")
        with open(p, "w") as f:
            f.write("var x = 1 + 2; function g(a){ return a * 3; }")
        r = analyze_file(p, True, 10 * 1024 * 1024)
        good = r["ast_nodes"] > 10 and r["total_call_expressions"] == 0
        ok &= good
        print(f"[{'PASS' if good else 'FAIL'}] ast_nodes counts all nodes (got {r['ast_nodes']})")

        # performance guard: a 3 MB run of identifier characters must not blow up
        p = os.path.join(tmp, "perf.js")
        with open(p, "w") as f:
            f.write("var s = '" + "a" * 3_000_000 + "'; require('fs').readFileSync('x');")
        t0 = time.time()
        r = analyze_file(p, True, 50 * 1024 * 1024)
        dt = time.time() - t0
        good = dt < 20
        ok &= good
        print(f"[{'PASS' if good else 'FAIL'}] 3 MB identifier run analysed in {dt:.1f}s")

    print("\nALL PASSED" if ok else "\nSOME CASES FAILED - do not run on the corpus yet")
    sys.exit(0 if ok else 1)


def main():
    if "--selftest" in sys.argv:
        run_selftest()

    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--label", required=True, choices=["benign", "malicious"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--layout", default="auto", choices=["auto", "versioned", "flat"])
    ap.add_argument("--no-alias", action="store_true")
    ap.add_argument("--include-node-modules", action="store_true")
    ap.add_argument("--max-file-mb", type=float, default=10)
    ap.add_argument("--skip-long-line", type=int, default=0,
                    help="skip files with a line longer than N chars (0 = off). "
                         "Skips are counted in skipped_minified.")
    ap.add_argument("--workers", type=int, default=max(1, cpu_count() - 1))
    a = ap.parse_args()
    logging.basicConfig(filename=f"{a.out}_analysis.log", level=logging.INFO)
    if ts_ts is None:
        print("WARNING: tree_sitter_typescript not installed; .ts parsed with the JS grammar "
              "(counted in ts_parsed_as_js). pip install tree-sitter-typescript")

    units = [(n, v, p, lay, why, not a.no_alias, a.include_node_modules,
              int(a.max_file_mb * 1024 * 1024), a.skip_long_line)
             for n, v, p, lay, why in enumerate_units(a.dataset, a.layout)]
    print(f"{len(units)} package-versions")

    rows, layout_rows = [], []
    t0 = time.time()
    with Pool(a.workers) as pool:
        for i, (pid, name, ver, lay, why, r) in enumerate(
                pool.imap_unordered(process_unit, units, chunksize=1), 1):
            rows.append((pid, r))
            layout_rows.append([pid, name, ver or "", lay, why])
            if i % 25 == 0 or i == len(units):
                print(f"{i}/{len(units)}  ({time.time() - t0:.0f}s)", flush=True)

    extra = ["total_call_expressions", "file_count", "code_bytes", "code_lines", "ast_nodes",
             "analyzable", "syntax_error_files", "ts_parsed_as_js", "skipped_large",
             "skipped_minified", "vendored_files_skipped", "parse_success",
             "read_error", "file_error", "worker_error"]
    with open(f"{a.out}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Package", "Label"] + CATS + extra)
        for pid, r in sorted(rows):
            w.writerow([pid, a.label] + [r.get(c, 0) for c in CATS] + [r.get(c, 0) for c in extra])
    with open(f"{a.out}_layout.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Package", "pkg_name", "version", "layout", "reason"])
        w.writerows(sorted(layout_rows))

    for c in glob.glob(".crumb_*"):
        try:
            os.remove(c)
        except OSError:
            pass
    amb = sum(1 for r in layout_rows if "CHECK" in r[4])
    errs = sum(1 for _, r in rows if r.get("worker_error") or r.get("file_error"))
    print(f"wrote {a.out}.csv ({len(rows)} rows); ambiguous layouts: {amb}; units with errors: {errs}")


if __name__ == "__main__":
    main()