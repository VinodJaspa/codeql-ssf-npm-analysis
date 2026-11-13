#!/usr/bin/env python3
"""
RQ4 publication figures: Raincloud plots and API prevalence.

Input columns:
    Package
    Label
    OS & File System
    Process Execution
    Network & HTTP
    Serialization & Buffer
    Encoding & Obfuscation
    code_bytes
    ast_nodes

Outputs:
    Figure 1: Source-code characteristics raincloud plots
    Figure 2: API-category count raincloud plots
    Figure 3: API-category prevalence with 95% Wilson CIs

Run:
  uv run python rq4_raincloud_figures.py \
    --malicious ../results/temporal-csv-rq4/malicious.csv \
    --benign ../results/temporal-csv-rq4/benign.csv \
    --output-dir ../results/rq4_raincloud_figures
"""

import argparse
import re
import html
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde


# ============================================================
# CONFIGURATION
# ============================================================

GROUPS = ["Benign", "Malicious"]

COLORS = {
    "Benign": "#3977A8",
    "Malicious": "#D36A45",
}

CATEGORY_COLUMNS = {
    "A — OS & File System": "OS & File System",
    "B — Process Execution": "Process Execution",
    "C — Network & HTTP": "Network & HTTP",
    "D — Serialization & Buffer": "Serialization & Buffer",
    "E — Encoding & Obfuscation": "Encoding & Obfuscation",
}

SOURCE_COLUMNS = {
    "Source-code size": "code_bytes",
    "AST node count": "ast_nodes",
}

RANDOM_SEED = 42
POINT_SIZE = 7
POINT_ALPHA = 0.18
POINT_LIMIT = 1800


# ============================================================
# PUBLICATION STYLE
# ============================================================

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.titlesize": 11,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.linewidth": 0.8,
        "figure.dpi": 150,
    }
)


# ============================================================
# DATA LOADING
# ============================================================


def normalize_header(value):
    value = html.unescape(str(value))
    value = value.replace("**", "")
    value = value.strip()
    value = re.sub(r"\s+", " ", value)
    return value.lower()


def load_data(malicious_file, benign_file):
    def read_group(path, group_name):

        df = pd.read_csv(path)

        df.columns = [normalize_header(c) for c in df.columns]

        aliases = {
            "package": "package",
            "label": "label",
            "code_bytes": "code_bytes",
            "ast_nodes": "ast_nodes",
            "os & file system": "OS & File System",
            "process execution": "Process Execution",
            "network & http": "Network & HTTP",
            "serialization & buffer": "Serialization & Buffer",
            "encoding & obfuscation": "Encoding & Obfuscation",
        }

        df = df.rename(columns={c: aliases[c] for c in df.columns if c in aliases})

        required = [
            "code_bytes",
            "ast_nodes",
            *CATEGORY_COLUMNS.values(),
        ]

        missing = [c for c in required if c not in df.columns]

        if missing:
            raise ValueError(f"{path}: missing columns {missing}")

        for col in required:
            df[col] = pd.to_numeric(df[col], errors="coerce")

            if (df[col].dropna() < 0).any():
                raise ValueError(f"{path}: negative values in {col}")

        df["group"] = group_name

        return df

    malicious = read_group(malicious_file, "Malicious")

    benign = read_group(benign_file, "Benign")

    df = pd.concat(
        [benign, malicious],
        ignore_index=True,
    )

    print("\nDataset summary")
    print("--------------------------")
    print("Benign:", len(benign))
    print("Malicious:", len(malicious))
    print("Total:", len(df))

    return df


# ============================================================
# RAINCLOUD COMPONENTS
# ============================================================


def draw_raincloud(
    ax,
    values,
    y,
    color,
    rng,
    point_limit=POINT_LIMIT,
):
    """
    Horizontal raincloud:
      Upper: probability density (half violin)
      Middle: IQR and median
      Lower: individual observations
      Diamond: mean
    """

    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]

    if len(values) == 0:
        return

    # --------------------------------------------------------
    # 1. Density distribution
    # --------------------------------------------------------

    if len(values) >= 3 and np.std(values) > 1e-9:

        low, high = np.percentile(values, [0.5, 99.5])

        if high > low:

            padding = (high - low) * 0.08

            grid = np.linspace(
                max(0, low - padding),
                high + padding,
                250,
            )

            try:
                kde = gaussian_kde(values)
                density = kde(grid)

                density = density / density.max()

                density = density * 0.29

                ax.fill_between(
                    grid,
                    y,
                    y + density,
                    color=color,
                    alpha=0.32,
                    linewidth=0,
                )

                ax.plot(
                    grid,
                    y + density,
                    color=color,
                    linewidth=0.9,
                )

            except (ValueError, np.linalg.LinAlgError):
                pass

    # --------------------------------------------------------
    # 2. Median and IQR
    # --------------------------------------------------------

    q1, median, q3 = np.percentile(
        values,
        [25, 50, 75],
    )

    ax.plot(
        [q1, q3],
        [y, y],
        color=color,
        linewidth=5,
        solid_capstyle="butt",
        zorder=4,
    )

    ax.plot(
        [median, median],
        [y - 0.07, y + 0.07],
        color="black",
        linewidth=1.8,
        zorder=5,
    )

    # --------------------------------------------------------
    # 3. Mean
    # --------------------------------------------------------

    mean = np.mean(values)

    ax.scatter(
        mean,
        y + 0.025,
        marker="D",
        s=25,
        facecolor="white",
        edgecolor="black",
        linewidth=0.8,
        zorder=6,
    )

    # --------------------------------------------------------
    # 4. Raw observations
    # --------------------------------------------------------

    points = values

    # Subsample only the displayed points for readability.
    # All observations are retained for statistical summaries.
    if len(points) > point_limit:
        points = rng.choice(
            points,
            size=point_limit,
            replace=False,
        )

    jitter = rng.uniform(
        -0.25,
        -0.10,
        size=len(points),
    )

    ax.scatter(
        points,
        y + jitter,
        s=POINT_SIZE,
        alpha=POINT_ALPHA,
        color=color,
        edgecolors="none",
        rasterized=True,
        zorder=2,
    )


# ============================================================
# GENERAL RAINCLOUD PANEL
# ============================================================


def plot_raincloud_panel(
    ax,
    df,
    column,
    title,
    rng,
):

    transformed = {}

    all_values = []

    for group in GROUPS:

        raw = (
            df.loc[
                df["group"] == group,
                column,
            ]
            .dropna()
            .to_numpy(dtype=float)
        )

      # Zero observations have already been excluded.
      # Apply log1p to positive observations.
        values = np.log1p(raw)

        transformed[group] = values
        all_values.extend(values.tolist())

    if not all_values:
        ax.set_title(title)
        return

    # Common horizontal scale within each panel.
    low, high = np.percentile(
        all_values,
        [0.5, 99.5],
    )

    if np.isclose(low, high):
        low -= 0.5
        high += 0.5

    xlim = (
        max(0, low - 0.08 * (high - low)),
        high + 0.08 * (high - low),
    )

    positions = {
        "Benign": 1,
        "Malicious": 0,
    }

    for group in GROUPS:

        draw_raincloud(
            ax,
            transformed[group],
            positions[group],
            COLORS[group],
            rng,
        )

    ax.set_yticks(
        [0, 1],
        ["Malicious", "Benign"],
    )

    ax.set_xlim(xlim)

    ax.set_ylim(-0.42, 1.48)

    ax.set_xlabel(f"log(1 + {column})")

    ax.set_title(
        title,
        loc="left",
        fontweight="bold",
    )

    ax.grid(
        axis="x",
        alpha=0.20,
        linewidth=0.7,
    )

    ax.set_axisbelow(True)


# ============================================================
# FIGURE 1: CODE CHARACTERISTICS
# ============================================================


def create_figure1(df, output_dir, rng):

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(11, 4.6),
    )

    plot_raincloud_panel(
        axes[0],
        df,
        "code_bytes",
        "(a) Source-code size",
        rng,
    )

    plot_raincloud_panel(
        axes[1],
        df,
        "ast_nodes",
        "(b) AST node count",
        rng,
    )

    # fig.suptitle(
    #     "Source-code characteristics by package label",
    #     fontsize=14,
    #     fontweight="bold",
    #     y=1.02,
    # )

    fig.text(
        0.5,
        -0.015,
        "Points represent observations; thick bars indicate IQR; "
        "black ticks indicate median; white diamonds indicate mean.",
        ha="center",
        fontsize=8,
    )

    fig.tight_layout()

    save_figure(
        fig,
        output_dir,
        "figure1_source_code_raincloud",
    )


# ============================================================
# FIGURE 2: API CATEGORY COUNTS
# ============================================================


def create_figure2(df, output_dir, rng):

    fig, axes = plt.subplots(
        2,
        3,
        figsize=(14, 8),
    )

    axes = axes.flatten()

    for i, (title, column) in enumerate(CATEGORY_COLUMNS.items()):

        plot_raincloud_panel(
            axes[i],
            df,
            column,
            title,
            rng,
        )

    axes[-1].axis("off")

    # fig.suptitle(
    #     "Package-level API-category count distributions",
    #     fontsize=15,
    #     fontweight="bold",
    # )

    fig.text(
        0.5,
        0.015,
        "Only packages with positive category counts are shown; "
        "values are transformed using log(1 + count).",
        ha="center",
        fontsize=9,
    )

    fig.tight_layout(rect=[0, 0.045, 1, 0.95])

    save_figure(
        fig,
        output_dir,
        "figure2_api_category_rainclouds",
    )


# ============================================================
# WILSON CONFIDENCE INTERVAL
# ============================================================


def wilson_interval(successes, total):

    if total == 0:
        return np.nan, np.nan, np.nan

    z = 1.959963984540054

    p = successes / total

    denominator = 1 + z**2 / total

    center = (p + z**2 / (2 * total)) / denominator

    margin = z * np.sqrt(p * (1 - p) / total + z**2 / (4 * total**2)) / denominator

    return (
        p,
        max(0, center - margin),
        min(1, center + margin),
    )


# ============================================================
# FIGURE 3: API CATEGORY PREVALENCE
# ============================================================


def create_figure3(df, output_dir):

    fig, ax = plt.subplots(figsize=(11, 5.8))

    categories = list(CATEGORY_COLUMNS.items())

    y_positions = np.arange(len(categories))[::-1]

    offsets = {
        "Benign": 0.12,
        "Malicious": -0.12,
    }

    results = []

    for y, (category, column) in zip(
        y_positions,
        categories,
    ):

        for group in GROUPS:

            values = df.loc[
                df["group"] == group,
                column,
            ].dropna()

            n = len(values)

            positive = int((values > 0).sum())

            p, lower, upper = wilson_interval(
                positive,
                n,
            )

            results.append(
                {
                    "category": category,
                    "group": group,
                    "positive_packages": positive,
                    "observed_packages": n,
                    "prevalence_percent": p * 100,
                    "ci95_lower_percent": lower * 100,
                    "ci95_upper_percent": upper * 100,
                }
            )

            if n == 0:
                continue

            position = y + offsets[group]

            ax.errorbar(
                p * 100,
                position,
                xerr=[
                    [(p - lower) * 100],
                    [(upper - p) * 100],
                ],
                fmt="o",
                color=COLORS[group],
                markersize=7,
                capsize=3,
                linewidth=1.5,
                zorder=3,
            )

            ax.text(
                min(upper * 100 + 1.5, 104),
                position,
                f"{positive}/{n}",
                fontsize=7.5,
                color=COLORS[group],
                va="center",
            )

    ax.set_yticks(
        y_positions,
        [category for category, _ in categories],
    )

    ax.set_xlim(0, 112)

    ax.set_xlabel("Packages with at least one category occurrence (%)")

    # ax.set_title(
    #     "API-category prevalence with 95% Wilson confidence intervals",
    #     loc="left",
    #     fontsize=13,
    #     fontweight="bold",
    # )

    ax.grid(
        axis="x",
        alpha=0.25,
    )

    from matplotlib.lines import Line2D

    handles = [
        Line2D(
            [0],
            [0],
            marker="o",
            color="none",
            markerfacecolor=COLORS[group],
            markeredgecolor=COLORS[group],
            label=group,
            markersize=7,
        )
        for group in GROUPS
    ]

    ax.legend(
        handles=handles,
        frameon=False,
        loc="lower right",
    )

    fig.tight_layout()

    save_figure(
        fig,
        output_dir,
        "figure3_api_category_prevalence",
    )

    pd.DataFrame(results).to_csv(
        output_dir / "api_category_prevalence.csv",
        index=False,
    )
# Exclude zero and negative values; retain missing values as missing.
def drop_zero_counts(df, columns):
    df = df.copy()
    for col in columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        # Drop rows where the count is less than or equal to 0
        df = df[df[col] > 0]
    return df

# ============================================================
# DESCRIPTIVE SUMMARY
# ============================================================


def create_summary(df, output_dir):

    measures = [
        "code_bytes",
        "ast_nodes",
        *CATEGORY_COLUMNS.values(),
    ]

    rows = []

    for column in measures:

        for group in GROUPS:

            values = df.loc[
                df["group"] == group,
                column,
            ].dropna()

            rows.append(
                {
                    "measure": column,
                    "group": group,
                    "n": len(values),
                    "mean": values.mean(),
                    "median": values.median(),
                    "q1": values.quantile(0.25),
                    "q3": values.quantile(0.75),
                    "min": values.min(),
                    "max": values.max(),
                    "zero_count": int((values == 0).sum()),
                    "zero_fraction": ((values == 0).mean() if len(values) else np.nan),
                }
            )

    pd.DataFrame(rows).to_csv(
        output_dir / "descriptive_summary.csv",
        index=False,
    )


# ============================================================
# FIGURE EXPORT
# ============================================================


def save_figure(fig, output_dir, filename):

    pdf = output_dir / f"{filename}.pdf"
    png = output_dir / f"{filename}.png"

    fig.savefig(
        pdf,
        bbox_inches="tight",
    )

    fig.savefig(
        png,
        dpi=600,
        bbox_inches="tight",
    )

    plt.close(fig)

    print(f"Saved: {pdf}")
    print(f"Saved: {png}")


# ============================================================
# MAIN
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="RQ4 publication figures: Positive-count raincloud plots"
    )

    parser.add_argument("--malicious", required=True, type=Path)
    parser.add_argument("--benign", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)

    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Load and combine datasets
    df = load_data(args.malicious, args.benign)

    # Exclude zero-count observations
    plot_columns = [
        "code_bytes",
        "ast_nodes",
        "OS & File System",
        "Process Execution",
        "Network & HTTP",
        "Serialization & Buffer",
        "Encoding & Obfuscation",
    ]

    df_clean = df[df['ast_nodes'] > 0].dropna(subset=['ast_nodes'])

    # Initialize reproducible random generator
    rng = np.random.default_rng(RANDOM_SEED)

    # Generate figures
    create_figure1(df_clean, args.output_dir, rng)
    create_figure2(df_clean, args.output_dir, rng)
    create_figure3(df_clean, args.output_dir)

   

    # Report retained observations separately for each measure
    print("\nPositive observations retained after zero filtering")
    print("=" * 60)
    for col in plot_columns:
        if col in df_clean.columns:
            # Count values greater than 0
            positive_count = (df_clean[col] > 0).sum()
            total_count = len(df_clean)
            pct = (positive_count / total_count) * 100
            print(f"{col}: {positive_count} / {total_count} ({pct:.2f}%)")
    print("=" * 60)

    print(f"\nFigures saved to: {args.output_dir}")


if __name__ == "__main__":
    main()