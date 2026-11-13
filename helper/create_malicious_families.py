import json
import html
import re
from pathlib import Path

import pandas as pd

INPUT_CSV = Path("../results/guarddog_summary_validation-set.csv")
OUTPUT_CSV = Path("../results/malicious_families_validation.csv")

df = pd.read_csv(INPUT_CSV)

# Normalize column names, including HTML-encoded names if present.
df.columns = [
    html.unescape(str(c)).replace("*", "").strip().lower()
    for c in df.columns
]

# Keep malicious records only.
df = df[df["label"].astype(str).str.lower().eq("malicious")].copy()

# Locate relevant columns.
path_col = next((c for c in df.columns if c == "path"), None)
hash_col = next((c for c in df.columns if c == "hash"), None)

if path_col is None:
    raise ValueError(f"No path column found. Available columns: {df.columns.tolist()}")

def make_rep_folder(row):
    package_path = Path(str(row[path_col]))
    package_name = str(row["package"]).strip()

    # Read version from package.json where available.
    version = str(row.get("version", "unknown"))
    package_json = package_path / "package.json"

    if package_json.exists():
        try:
            with package_json.open(encoding="utf-8") as f:
                version = str(json.load(f).get("version", version))
        except (OSError, json.JSONDecodeError):
            pass

    # Use the existing hash, shortened to 12 characters.
    digest = ""
    if hash_col and pd.notna(row.get(hash_col)):
        digest = re.sub(r"[^a-fA-F0-9]", "", str(row[hash_col]))

    if not digest:
        return None  # Do not invent a hash.

    return f"{package_name}__{version}__{digest[:12]}"

df["rep_folder"] = df.apply(make_rep_folder, axis=1)

result = (
    df.loc[df["rep_folder"].notna(), ["rep_folder"]]
    .drop_duplicates()
    .sort_values("rep_folder")
)

OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
result.to_csv(OUTPUT_CSV, index=False)

print(f"Malicious records: {len(df)}")
print(f"Unique rep_folder entries: {len(result)}")
print(f"Saved to: {OUTPUT_CSV.resolve()}")
print(result.head(10).to_string(index=False))