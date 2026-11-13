
#!/usr/bin/env python3
"""Build and extract a reproducible 1,500-package DataDog npm corpus."""

import csv
import hashlib
import random
import re
import zipfile
from pathlib import Path, PurePosixPath

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
REPO = Path("malicious-software-packages-dataset")
SAMPLES = REPO / "samples" / "npm" / "malicious_intent"
OUT = Path("datadog_npm_malicious_intent")

SAMPLE_SIZE = 1500
SEED = 42
ZIP_PASSWORD = b"infected"

EXTRACT_DIR = "../temporal_corups"
OUT.mkdir(parents=True, exist_ok=True)
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path, rows):
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fields = list(dict.fromkeys(
        key for row in rows for key in row
    ))

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def has_readable_js(archive):
    """Return a readable, non-empty .js member, if present."""
    for member in archive.infolist():
        if member.is_dir() or not member.filename.lower().endswith(".js"):
            continue

        try:
            data = archive.read(member, pwd=ZIP_PASSWORD)
            if not data.strip():
                continue

            # Require text that decodes as UTF-8.
            data.decode("utf-8-sig")
            return member.filename

        except (RuntimeError, UnicodeDecodeError, OSError, EOFError):
            continue

    return None


def safe_extract(archive, destination):
    """Extract archive members without allowing path traversal."""
    destination = destination.resolve()
    extracted_count = 0

    for member in archive.infolist():
        if member.is_dir():
            continue

        # DataDog ZIP member paths should be relative paths.
        member_path = PurePosixPath(member.filename)
        if member_path.is_absolute() or ".." in member_path.parts:
            continue

        target = (destination / Path(*member_path.parts)).resolve()

        if not target.is_relative_to(destination):
            continue

        target.parent.mkdir(parents=True, exist_ok=True)

        try:
            with archive.open(member, pwd=ZIP_PASSWORD) as source:
                with target.open("wb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)

            extracted_count += 1

        except (RuntimeError, OSError, EOFError, zipfile.BadZipFile):
            # Record extraction failures in the audit.
            continue

    return extracted_count


# ------------------------------------------------------------
# Validate input
# ------------------------------------------------------------
if not SAMPLES.is_dir():
    raise FileNotFoundError(
        f"DataDog npm malicious_intent folder not found:\n"
        f"{SAMPLES.resolve()}\n"
        "Check the repository path and sparse checkout."
    )


# ------------------------------------------------------------
# Scan original DataDog ZIP artifacts
# ------------------------------------------------------------
candidates = []
audit = []

zip_paths = sorted(SAMPLES.rglob("*.zip"))

print(f"ZIP archives discovered: {len(zip_paths)}")

for index, zip_path in enumerate(zip_paths, 1):
    relative = zip_path.relative_to(SAMPLES)
    parts = relative.parts

    # Expected: package-name/version/sample.zip
    if len(parts) < 3:
        audit.append({
            "datadog_zip": str(zip_path.resolve()),
            "status": "unexpected_directory_layout",
        })
        continue

    package_name, version = parts[0], parts[1]

    date_match = re.match(
        r"^(\d{4}-\d{2}-\d{2})-", zip_path.name
    )
    discovery_date = date_match.group(1) if date_match else ""

    try:
        digest = sha256_file(zip_path)

        with zipfile.ZipFile(zip_path) as archive:
            js_member = has_readable_js(archive)

        if not js_member:
            audit.append({
                "package": package_name,
                "version": version,
                "datadog_zip": str(zip_path.resolve()),
                "zip_sha256": digest,
                "status": "excluded_no_readable_nonempty_js",
            })
            continue

        candidates.append({
            "package": package_name,
            "version": version,
            "discovery_date": discovery_date,
            "datadog_zip": str(zip_path.resolve()),
            "zip_sha256": digest,
            "js_member": js_member,
        })

    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        audit.append({
            "package": package_name,
            "version": version,
            "datadog_zip": str(zip_path.resolve()),
            "status": "zip_validation_error",
            "error": str(exc)[:300],
        })

    if index % 1000 == 0:
        print(f"Scanned {index}/{len(zip_paths)} ZIPs")


# ------------------------------------------------------------
# Deduplicate: one artifact per package name and unique ZIP hash
# ------------------------------------------------------------
candidates.sort(key=lambda row: (
    row["discovery_date"] or "9999-99-99",
    row["package"].lower(),
    row["version"],
    row["zip_sha256"],
))

unique = []
seen_names = set()
seen_hashes = set()

for row in candidates:
    name_key = row["package"].lower()
    digest = row["zip_sha256"]

    if name_key in seen_names:
        audit.append({
            **row,
            "status": "excluded_duplicate_package_name",
        })
        continue

    if digest in seen_hashes:
        audit.append({
            **row,
            "status": "excluded_duplicate_zip_sha256",
        })
        continue

    seen_names.add(name_key)
    seen_hashes.add(digest)
    unique.append(row)


# ------------------------------------------------------------
# Select exactly 1,500 packages using a fixed random seed
# ------------------------------------------------------------
if len(unique) < SAMPLE_SIZE:
    raise ValueError(
        f"Only {len(unique)} unique packages with readable JS "
        f"were found; {SAMPLE_SIZE} are required."
    )

rng = random.Random(SEED)
evaluation = rng.sample(unique, SAMPLE_SIZE)

print(f"ZIPs with readable JS: {len(candidates)}")
print(f"Unique eligible packages: {len(unique)}")
print(f"Selected packages: {len(evaluation)}")


# ------------------------------------------------------------
# Extract selected DataDog ZIPs
# ------------------------------------------------------------
extraction_records = []

for index, row in enumerate(evaluation, 1):
    zip_path = Path(row["datadog_zip"])

    folder_name = (
        f"{safe_name(row['package'])}__"
        f"{safe_name(row['version'])}__"
        f"{row['zip_sha256'][:12]}"
    )
    package_dir = EXTRACT_DIR / folder_name

    package_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path) as archive:
            extracted_count = safe_extract(archive, package_dir)

        # Confirm that at least one readable, non-empty JS file
        # exists in the extracted tree.
        js_files = [
            p for p in package_dir.rglob("*")
            if p.is_file() and p.suffix.lower() == ".js"
        ]

        valid_js_files = []
        for js_path in js_files:
            try:
                if js_path.stat().st_size == 0:
                    continue
                js_path.read_text(encoding="utf-8-sig")
                valid_js_files.append(js_path)
            except (OSError, UnicodeDecodeError):
                continue

        if not valid_js_files:
            extraction_records.append({
                **row,
                "extraction_directory": str(package_dir.resolve()),
                "extracted_files": extracted_count,
                "status": "extraction_failed_no_valid_js",
            })
            continue

        extraction_records.append({
            **row,
            "extraction_directory": str(package_dir.resolve()),
            "extracted_files": extracted_count,
            "valid_js_files": len(valid_js_files),
            "status": "extracted",
        })

    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        extraction_records.append({
            **row,
            "extraction_directory": str(package_dir.resolve()),
            "status": "extraction_error",
            "error": str(exc)[:300],
        })

    if index % 100 == 0:
        print(f"Processed extraction {index}/{len(evaluation)}")


# ------------------------------------------------------------
# Save outputs and audit trail
# ------------------------------------------------------------
write_csv(OUT / "evaluation_1500.csv", evaluation)
write_csv(OUT / "extraction_manifest.csv", extraction_records)

selected_keys = {
    (row["package"].lower(), row["zip_sha256"])
    for row in evaluation
}

for row in unique:
    audit.append({
        **row,
        "status": (
            "selected_for_evaluation"
            if (row["package"].lower(), row["zip_sha256"])
            in selected_keys
            else "eligible_not_sampled"
        ),
    })

write_csv(OUT / "audit.csv", audit)

successful = sum(
    record["status"] == "extracted"
    for record in extraction_records
)

print("\n========== SUMMARY ==========")
print(f"DataDog ZIPs discovered: {len(zip_paths)}")
print(f"ZIPs containing readable JS: {len(candidates)}")
print(f"Unique eligible packages: {len(unique)}")
print(f"Selected packages: {len(evaluation)}")
print(f"Successfully extracted: {successful}")
print(f"Extraction directory: {EXTRACT_DIR.resolve()}")
print(f"Evaluation manifest: {(OUT / 'evaluation_1500.csv').resolve()}")
print(f"Extraction manifest: {(OUT / 'extraction_manifest.csv').resolve()}")
print(f"Audit trail: {(OUT / 'audit.csv').resolve()}")
