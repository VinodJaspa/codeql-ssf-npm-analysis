
from pathlib import Path
from itertools import combinations

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from scipy.stats import fisher_exact
from statsmodels.stats.multitest import multipletests


# ============================================================
# 1. CONFIGURATION
# ============================================================

malicious_csv = Path("../results/temporal-csv-rq4/malicious.csv")
benign_csv = Path("../results/temporal-csv-rq4/benign.csv")

OUTPUT = Path("behavioral_coordination_results")
OUTPUT.mkdir(parents=True, exist_ok=True)

SEED = 42
BOOTSTRAPS = 3000
PERMUTATIONS = 5000

CATEGORIES = [
    "OS & File System",
    "Process Execution",
    "Network & HTTP",
    "Serialization & Buffer",
    "Encoding & Obfuscation",
]

SHORT_NAMES = [
    "OS/File",
    "Process",
    "Network",
    "Serialization",
    "Encoding",
]

COLORS = {
    "malicious": "#C44E52",
    "benign": "#4C72B0",
}

rng = np.random.default_rng(SEED)

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.labelsize": 9,
    "axes.titlesize": 10,
    "savefig.dpi": 600,
    "axes.spines.top": False,
    "axes.spines.right": False,
})


# ============================================================
# 2. LOAD AND VALIDATE DATA
# ============================================================

for path in [malicious_csv, benign_csv]:
    if not path.is_file():
        raise FileNotFoundError(
            f"CSV not found: {path.resolve()}"
        )

df = pd.concat(
    [
        pd.read_csv(malicious_csv),
        pd.read_csv(benign_csv),
    ],
    ignore_index=True,
)

# Clean Markdown/HTML artifacts from column names.
df.columns = (
    df.columns.astype(str)
    .str.replace(r"^\*+", "", regex=True)
    .str.replace(r"&#x[0-9a-fA-F]+;", "", regex=True)
    .str.strip()
)

required = ["Package", "Label"] + CATEGORIES
missing = set(required) - set(df.columns)

if missing:
    raise ValueError(
        f"Missing columns: {sorted(missing)}"
    )

df["Label"] = (
    df["Label"]
    .astype(str)
    .str.lower()
    .str.strip()
)

df = df[
    df["Label"].isin(["malicious", "benign"])
].copy()

for col in CATEGORIES:
    df[col] = pd.to_numeric(
        df[col],
        errors="coerce"
    )

# Missing API measurements are not treated as zero.
df = df.dropna(subset=CATEGORIES).copy()

# Restrict to analyzable observations if the field exists.
# Packages excluded from analysis
for name, df in [
    ("benign", df),
    ("malicious", df),
]:
    print(f"\n{name} restricted packages:")

    if "analyzable" in df.columns:
        restricted = df[df["analyzable"] == False]

        print("Restricted count:", len(restricted))
        print(restricted[["Package", "analyzable"]].to_string(index=False))
    else:
        print("No analyzable column found.")

if "analyzable" in df.columns:

    valid = (
        df["analyzable"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    df = df[
        valid.isin(["1", "1.0", "true"])
    ].copy()

if (df[CATEGORIES] < 0).any().any():
    raise ValueError(
        "Negative API counts detected."
    )

if df["Package"].duplicated().any():
    print(
        "\nWARNING: Duplicate Package identifiers detected."
    )
    print(
        "Check whether multiple versions of the same package "
        "are present. Statistical resampling may need to be "
        "performed at package-family level."
    )

if not {"malicious", "benign"}.issubset(
    set(df["Label"])
):
    raise ValueError(
        "Both benign and malicious observations are required."
    )

print("\nAnalysis population:")
print(df["Label"].value_counts())

print("\nParsing quality:")

for col in [
    "parse_success",
    "syntax_error_files",
    "file_error",
    "worker_error",
]:
    if col in df.columns:
        print(
            col,
            df[col].value_counts(dropna=False).to_dict()
        )


# ============================================================
# 3. CREATE BINARY CATEGORY PRESENCE MATRIX
# ============================================================

# 1 = category present
# 0 = category absent

binary = df[CATEGORIES].gt(0).astype(int)

groups = {
    label: binary.loc[
        df["Label"].eq(label)
    ].to_numpy()
    for label in ["malicious", "benign"]
}

counts = {
    label: df.loc[
        df["Label"].eq(label), CATEGORIES
    ]
    for label in ["malicious", "benign"]
}

mal = groups["malicious"]
ben = groups["benign"]

n_mal = len(mal)
n_ben = len(ben)

print(f"\nMalicious observations: {n_mal}")
print(f"Benign observations: {n_ben}")


# ============================================================
# 4. PHI COEFFICIENT AND ASSOCIATION MATRICES
# ============================================================

def phi_coefficient(x, y):

    x = np.asarray(x)
    y = np.asarray(y)

    if (
        len(x) == 0
        or np.std(x) == 0
        or np.std(y) == 0
    ):
        return np.nan

    return np.corrcoef(x, y)[0, 1]


def association_matrix(data):

    p = data.shape[1]

    matrix = np.eye(p)

    for i, j in combinations(range(p), 2):

        value = phi_coefficient(
            data[:, i],
            data[:, j]
        )

        matrix[i, j] = value
        matrix[j, i] = value

    return matrix


phi_mal = association_matrix(mal)
phi_ben = association_matrix(ben)


# ============================================================
# 5. BOOTSTRAP CONFIDENCE INTERVAL FOR DIFFERENTIAL PHI
# ============================================================

def bootstrap_phi_difference(
    a,
    b,
    i,
    j,
):

    estimates = []

    for _ in range(BOOTSTRAPS):

        ai = a[
            rng.integers(0, len(a), len(a))
        ]

        bi = b[
            rng.integers(0, len(b), len(b))
        ]

        pm = phi_coefficient(
            ai[:, i],
            ai[:, j]
        )

        pb = phi_coefficient(
            bi[:, i],
            bi[:, j]
        )

        if np.isfinite(pm) and np.isfinite(pb):
            estimates.append(pm - pb)

    if len(estimates) < BOOTSTRAPS * 0.8:
        return np.nan, np.nan

    return np.percentile(
        estimates,
        [2.5, 97.5]
    )


# ============================================================
# 6. PERMUTATION TEST FOR DIFFERENTIAL PHI
# ============================================================

def permutation_phi_test(
    a,
    b,
    i,
    j,
):

    observed = (
        phi_coefficient(a[:, i], a[:, j])
        -
        phi_coefficient(b[:, i], b[:, j])
    )

    if not np.isfinite(observed):
        return np.nan

    combined = np.vstack([a, b])
    n_a = len(a)

    extreme = 0
    valid = 0

    for _ in range(PERMUTATIONS):

        shuffled = combined[
            rng.permutation(len(combined))
        ]

        aa = shuffled[:n_a]
        bb = shuffled[n_a:]

        difference = (
            phi_coefficient(aa[:, i], aa[:, j])
            -
            phi_coefficient(bb[:, i], bb[:, j])
        )

        if np.isfinite(difference):

            valid += 1

            if abs(difference) >= abs(observed):
                extreme += 1

    if valid == 0:
        return np.nan

    return (extreme + 1) / (valid + 1)


# ============================================================
# 7. PAIRWISE DIFFERENTIAL COORDINATION
# ============================================================

pair_results = []

for i, j in combinations(
    range(len(CATEGORIES)), 2
):

    pm = phi_mal[i, j]
    pb = phi_ben[i, j]

    if not np.isfinite(pm) or not np.isfinite(pb):
        continue

    low, high = bootstrap_phi_difference(
        mal,
        ben,
        i,
        j,
    )

    p_value = permutation_phi_test(
        mal,
        ben,
        i,
        j,
    )

    pair_results.append({

        "Category_1": CATEGORIES[i],
        "Category_2": CATEGORIES[j],

        "Phi_Malicious": pm,
        "Phi_Benign": pb,

        "Delta_Phi": pm - pb,

        "CI_Lower": low,
        "CI_Upper": high,

        "P_Value": p_value,
    })


pair_df = pd.DataFrame(pair_results)

if not pair_df.empty:

    pair_df["P_Adjusted"] = np.nan

    valid_p = pair_df["P_Value"].notna()

    pair_df.loc[
        valid_p, "P_Adjusted"
    ] = multipletests(
        pair_df.loc[valid_p, "P_Value"],
        method="holm",
    )[1]

    pair_df.to_csv(
        OUTPUT / "differential_coordination.csv",
        index=False,
    )





# ============================================================
# 9. FIGURES 2 AND 3: SEPARATE PHI HEATMAPS
# ============================================================

def save_heatmap(
    matrix,
    filename,
):

    fig, ax = plt.subplots(
        figsize=(7, 6)
    )

    image = ax.imshow(
        matrix,
        cmap="RdBu_r",
        vmin=-1,
        vmax=1,
        interpolation="nearest",
    )

    ax.set_xticks(range(5))
    ax.set_yticks(range(5))

    ax.set_xticklabels(
        SHORT_NAMES,
        rotation=35,
        ha="right",
    )

    ax.set_yticklabels(SHORT_NAMES)

    # Adaptive annotation colours.
    for i in range(5):

        for j in range(5):

            value = matrix[i, j]

            if np.isfinite(value):

                text_color = (
                    "white"
                    if abs(value) >= 0.65
                    else "black"
                )

                ax.text(
                    j,
                    i,
                    f"{value:.2f}",

                    ha="center",
                    va="center",

                    fontsize=9,
                    fontweight="medium",
                    color=text_color,
                )

    fig.colorbar(
        image,
        ax=ax,
        shrink=0.8,
        label="Phi coefficient",
    )

    fig.tight_layout()

    fig.savefig(
        OUTPUT / filename,
        bbox_inches="tight",
    )

    plt.close(fig)


save_heatmap(
    phi_mal,
    "malicious_phi_heatmap.pdf",
)

save_heatmap(
    phi_ben,
    "benign_phi_heatmap.pdf",
)


# ============================================================
# 10. FIGURE 4: DIFFERENTIAL PAIRWISE COORDINATION
# ============================================================

if not pair_df.empty:

    plot_df = pair_df.dropna(
        subset=[
            "Delta_Phi",
            "CI_Lower",
            "CI_Upper",
        ]
    ).sort_values("Delta_Phi")

    if not plot_df.empty:

        fig, ax = plt.subplots(
            figsize=(9, 6)
        )

        y = np.arange(len(plot_df))

        ax.errorbar(
            plot_df["Delta_Phi"],
            y,

            xerr=[
                (
                    plot_df["Delta_Phi"]
                    - plot_df["CI_Lower"]
                ),

                (
                    plot_df["CI_Upper"]
                    - plot_df["Delta_Phi"]
                ),
            ],

            fmt="o",
            capsize=3,
            markersize=5,
            color="#333333",
        )

        ax.axvline(
            0,
            linestyle="--",
            color="gray",
            linewidth=1,
        )

        labels = [
            (
                f"{row.Category_1.replace(' & ', '/')}"
                f" – "
                f"{row.Category_2.replace(' & ', '/')}"
            )
            for row in plot_df.itertuples()
        ]

        ax.set_yticks(y)
        ax.set_yticklabels(labels)

        ax.set_xlabel(
            "Difference in phi (malicious − benign)"
        )

        fig.tight_layout()

        fig.savefig(
            OUTPUT / "differential_coordination.pdf",
            bbox_inches="tight",
        )

        fig.savefig(
            OUTPUT / "differential_coordination.png",
            bbox_inches="tight",
        )

        plt.close(fig)


# ============================================================
# 11. ALL 26 COMBINATION PREVALENCE ANALYSES
# ============================================================

combination_results = []

for size in range(
    1,
    len(CATEGORIES) + 1
):

    for indices in combinations(
        range(len(CATEGORIES)),
        size,
    ):

        # Every selected category must be present.
        # Other categories may also be present.

        mal_mask = np.all(
            mal[:, indices] == 1,
            axis=1,
        )

        ben_mask = np.all(
            ben[:, indices] == 1,
            axis=1,
        )

        mal_count = int(mal_mask.sum())
        ben_count = int(ben_mask.sum())

        mal_pct = (
            100 * mal_count / n_mal
        )

        ben_pct = (
            100 * ben_count / n_ben
        )

        odds_ratio, p_value = fisher_exact(
            [
                [
                    mal_count,
                    n_mal - mal_count,
                ],
                [
                    ben_count,
                    n_ben - ben_count,
                ],
            ],
            alternative="two-sided",
        )

        # Bootstrap prevalence difference.
        boot_differences = []

        for _ in range(BOOTSTRAPS):

            sampled_mal = rng.choice(
                mal_mask,
                size=n_mal,
                replace=True,
            )

            sampled_ben = rng.choice(
                ben_mask,
                size=n_ben,
                replace=True,
            )

            difference = 100 * (
                sampled_mal.mean()
                -
                sampled_ben.mean()
            )

            boot_differences.append(difference)

        ci_low, ci_high = np.percentile(
            boot_differences,
            [2.5, 97.5],
        )

        combination_name = " + ".join(
            SHORT_NAMES[i]
            for i in indices
        )

        combination_results.append({

            "Combination": combination_name,

            "Number_of_Categories": size,

            "Malicious_Count": mal_count,
            "Malicious_Percentage": mal_pct,

            "Benign_Count": ben_count,
            "Benign_Percentage": ben_pct,

            "Difference_Percentage_Points": (
                mal_pct - ben_pct
            ),

            "CI_Lower": ci_low,
            "CI_Upper": ci_high,

            "Odds_Ratio": odds_ratio,
            "P_Value": p_value,
        })


combination_df = pd.DataFrame(
    combination_results
)

# Holm correction across all 26 combinations.
combination_df["P_Adjusted"] = multipletests(
    combination_df["P_Value"],
    method="holm",
)[1]

combination_df["Significant"] = (
    combination_df["P_Adjusted"] < 0.05
)

combination_df = combination_df.sort_values(
    "Difference_Percentage_Points",
    ascending=False,
)

combination_df.to_csv(
    OUTPUT / "all_26_combination_prevalence.csv",
    index=False,
)

print("\nAll 26 combination results:")

print(
    combination_df[
        [
            "Combination",
            "Malicious_Count",
            "Malicious_Percentage",
            "Benign_Count",
            "Benign_Percentage",
            "Difference_Percentage_Points",
            "P_Adjusted",
        ]
    ].to_string(index=False)
)


# ============================================================
# 12. FIGURE 5: DIFFERENTIAL COMBINATION PREVALENCE
# ============================================================

plot_df = combination_df.sort_values(
    "Difference_Percentage_Points"
).copy()

fig, ax = plt.subplots(
    figsize=(12, 11)
)

y = np.arange(len(plot_df))

for k, (_, row) in enumerate(
    plot_df.iterrows()
):

    color = (
        COLORS["malicious"]
        if row["Significant"]
        else "#555555"
    )

    ax.errorbar(
        row["Difference_Percentage_Points"],
        k,

        xerr=[[
            row["Difference_Percentage_Points"]
            - row["CI_Lower"]
        ], [
            row["CI_Upper"]
            - row["Difference_Percentage_Points"]
        ]],

        fmt="o",
        color=color,
        capsize=3,
        markersize=5,
        linewidth=1.2,
    )

ax.axvline(
    0,
    linestyle="--",
    color="black",
    linewidth=1,
)

ax.set_yticks(y)

ax.set_yticklabels(
    plot_df["Combination"],
    fontsize=9,
)

ax.set_xlabel(
    "Prevalence difference "
    "(malicious − benign), percentage points"
)

ax.grid(
    axis="x",
    alpha=0.2,
)

fig.tight_layout()

fig.savefig(
    OUTPUT / "combination_prevalence.pdf",
    bbox_inches="tight",
)

fig.savefig(
    OUTPUT / "combination_prevalence.png",
    bbox_inches="tight",
)

plt.close(fig)


# ============================================================
# 13. EXACT BEHAVIORAL PROFILES — CSV ONLY
# ============================================================

profile_rows = []

# All 32 possible five-bit patterns.
all_patterns = [
    format(i, "05b")
    for i in range(32)
]

for label, matrix in [
    ("malicious", mal),
    ("benign", ben),
]:

    observed = pd.Series(
        [
            "".join(map(str, row))
            for row in matrix
        ]
    ).value_counts()

    pattern_counts = observed.reindex(
        all_patterns,
        fill_value=0,
    )

    for pattern, count in pattern_counts.items():

        if pattern == "00000":

            name = "No sensitive categories"

        else:

            name = " + ".join(
                SHORT_NAMES[i]
                for i, value in enumerate(pattern)
                if value == "1"
            )

        profile_rows.append({

            "Pattern_Code": pattern,
            "Exact_Profile": name,
            "Label": label,

            "Count": int(count),

            "Percentage": (
                100 * count / len(matrix)
            ),
        })


profiles = pd.DataFrame(profile_rows)

profiles.to_csv(
    OUTPUT / "exact_behavioral_profiles.csv",
    index=False,
)


# ============================================================
# 14. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("BEHAVIORAL COORDINATION ANALYSIS COMPLETED")
print("=" * 60)

print(f"\nMalicious observations: {n_mal}")
print(f"Benign observations: {n_ben}")

print(
    f"Pairwise comparisons: {len(pair_df)}"
)

print(
    f"Combination comparisons: {len(combination_df)}"
)

print(
    f"Exact behavioral profiles: {len(profiles)}"
)

print("\nOutput directory:")
print(OUTPUT.resolve())

print("\nGenerated figures:")

for filename in [
    "api_intensity.pdf",
    "malicious_phi_heatmap.pdf",
    "benign_phi_heatmap.pdf",
    "differential_coordination.pdf",
    "combination_prevalence.pdf",
]:
    print(" -", filename)

print("\nGenerated CSV files:")

for filename in [
    "differential_coordination.csv",
    "all_26_combination_prevalence.csv",
    "exact_behavioral_profiles.csv",
]:
    print(" -", filename)

print("\nDone.")
