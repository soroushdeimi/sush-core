#!/usr/bin/env python3
"""
Analyze and visualize benchmark results for publication.
"""

import sys
from pathlib import Path

# Add project root to path if needed
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Setup paths
DATA_DIR = Path("tests/data")
CSV_FILE = DATA_DIR / "benchmark_results.csv"
PLOTS_DIR = DATA_DIR / "plots"
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

# Matplotlib style
plt.style.use("seaborn-v0_8-darkgrid")
plt.rcParams["figure.figsize"] = (12, 7)
plt.rcParams["font.size"] = 11
plt.rcParams["axes.labelsize"] = 12
plt.rcParams["axes.titlesize"] = 14
plt.rcParams["xtick.labelsize"] = 10
plt.rcParams["ytick.labelsize"] = 10
plt.rcParams["legend.fontsize"] = 10


def load_data():
    """Load benchmark results from CSV."""
    if not CSV_FILE.exists():
        print(f"Error: {CSV_FILE} not found. Run tests/run_benchmarks.py first.")
        sys.exit(1)

    df = pd.read_csv(CSV_FILE)
    print(f"Loaded {len(df)} data points from {CSV_FILE}")
    return df


def plot_crypto_overhead(df):
    """Plot 1: Crypto overhead analysis - encryption time per MB."""
    exp_a = df[df["experiment"] == "A"].copy()

    if exp_a.empty:
        print("Warning: No Experiment A data found")
        return

    # Convert payload sizes to MB
    exp_a["payload_size_mb"] = exp_a["payload_size_bytes"] / (1024 * 1024)

    # Calculate time per MB
    exp_a["time_per_mb_ms"] = (exp_a["avg_total_time_ms"] / exp_a["payload_size_mb"]).replace(
        [np.inf, -np.inf], np.nan
    )

    # Create bar chart
    fig, ax = plt.subplots()

    sizes = sorted(exp_a["payload_size_bytes"].unique())
    x = np.arange(len(sizes))
    width = 0.6

    time_per_mb = []
    std_values = []

    for size in sizes:
        size_data = exp_a[exp_a["payload_size_bytes"] == size]
        if not size_data.empty:
            time_per_mb.append(size_data["time_per_mb_ms"].iloc[0])
            # Use std of total time as error bar
            std_values.append(size_data["std_total_time_ms"].iloc[0] / (size / (1024 * 1024)))
        else:
            time_per_mb.append(0)
            std_values.append(0)

    bars = ax.bar(x, time_per_mb, width, yerr=std_values, alpha=0.8, capsize=5, color="steelblue")

    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, time_per_mb)):
        if not np.isnan(val) and val > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                bar.get_height(),
                f"{val:.2f}",
                ha="center",
                va="bottom",
                fontsize=9,
            )

    ax.set_xlabel("Payload Size")
    ax.set_ylabel("Processing Time per MB (ms)")
    ax.set_title("Crypto Overhead Analysis: Encryption Time per MB")
    ax.set_xticks(x)
    ax.set_xticklabels(
        [
            f"{s/1024:.0f}KB" if s < 1024 * 1024 else f"{s/(1024*1024):.0f}MB"
            for s in sizes
        ]
    )
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "crypto_overhead.png", dpi=300, bbox_inches="tight")
    plt.savefig(PLOTS_DIR / "crypto_overhead.pdf", bbox_inches="tight")
    print(f"Saved: {PLOTS_DIR / 'crypto_overhead.png'}")

    plt.close()


def plot_throughput_comparison(df):
    """Plot 2: Comparison of Direct vs. Steganographic throughput."""
    exp_b = df[df["experiment"] == "B"].copy()

    if exp_b.empty:
        print("Warning: No Experiment B data found")
        return

    # Group by mode
    direct_data = exp_b[exp_b["mode"] == "DIRECT"]
    stego_data = exp_b[exp_b["mode"] == "STEGANOGRAPHIC"]

    fig, ax = plt.subplots()

    modes = []
    throughputs = []
    colors = []

    if not direct_data.empty:
        modes.append("DIRECT")
        throughputs.append(direct_data["effective_throughput_mbps"].iloc[0])
        colors.append("steelblue")

    if not stego_data.empty:
        modes.append("STEGANOGRAPHIC")
        throughputs.append(stego_data["effective_throughput_mbps"].iloc[0])
        colors.append("crimson")

    if not modes:
        print("Warning: No throughput data available")
        return

    x = np.arange(len(modes))
    width = 0.6

    bars = ax.bar(x, throughputs, width, alpha=0.8, color=colors)

    # Add value labels
    for bar, val in zip(bars, throughputs):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height(),
            f"{val:.2f}",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
        )

    ax.set_xlabel("Transport Mode")
    ax.set_ylabel("Effective Throughput (Mbps)")
    ax.set_title("End-to-End Throughput Comparison: Direct vs. Steganographic")
    ax.set_xticks(x)
    ax.set_xticklabels(modes)
    ax.grid(True, alpha=0.3, axis="y")

    # Add percentage difference annotation
    if len(throughputs) == 2:
        diff_percent = ((throughputs[1] - throughputs[0]) / throughputs[0]) * 100
        ax.text(
            0.5,
            0.95,
            f"Overhead: {abs(diff_percent):.1f}%",
            transform=ax.transAxes,
            ha="center",
            va="top",
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
            fontsize=10,
        )

    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "throughput_comparison.png", dpi=300, bbox_inches="tight")
    plt.savefig(PLOTS_DIR / "throughput_comparison.pdf", bbox_inches="tight")
    print(f"Saved: {PLOTS_DIR / 'throughput_comparison.png'}")

    plt.close()


def plot_reaction_time(df):
    """Plot 3: Timeline showing attack event vs. adaptation event."""
    exp_c = df[df["experiment"] == "C"].copy()

    if exp_c.empty:
        print("Warning: No Experiment C data found")
        return

    # Filter out rows with no reaction time
    exp_c = exp_c[exp_c["reaction_time_ms"].notna()]

    if exp_c.empty:
        print("Warning: No adaptation events detected in Experiment C")
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    # Create timeline
    attack_time = 0  # Attack injected at T=0
    reaction_times = exp_c["reaction_time_ms"].values

    # Plot attack event
    ax.axvline(x=attack_time, color="red", linestyle="--", linewidth=2, label="Attack Injected (T=0)")

    # Plot adaptation events
    for i, reaction_time in enumerate(reaction_times):
        ax.axvline(
            x=reaction_time,
            color="green",
            linestyle="-",
            linewidth=2,
            alpha=0.7,
            label="Adaptation Detected" if i == 0 else "",
        )

        # Add annotation
        ax.annotate(
            f"{reaction_time:.1f}ms",
            xy=(reaction_time, 0.5),
            xytext=(reaction_time, 0.7),
            arrowprops=dict(arrowstyle="->", color="green", alpha=0.7),
            fontsize=9,
            ha="center",
        )

    # Calculate statistics
    mean_reaction = np.mean(reaction_times)
    std_reaction = np.std(reaction_times)

    ax.axvline(
        x=mean_reaction,
        color="blue",
        linestyle=":",
        linewidth=2,
        label=f"Mean: {mean_reaction:.1f}ms",
    )

    ax.set_xlabel("Time (ms)")
    ax.set_ylabel("Event")
    ax.set_title("Adaptive Control Response Time: Attack Detection to Adaptation")
    ax.set_xlim(-50, max(reaction_times) * 1.2)
    ax.set_ylim(0, 1)
    ax.set_yticks([])
    ax.legend(loc="upper right")
    ax.grid(True, alpha=0.3, axis="x")

    # Add statistics text
    stats_text = f"Mean: {mean_reaction:.2f}ms\nStd: {std_reaction:.2f}ms\nN: {len(reaction_times)}"
    ax.text(
        0.02,
        0.98,
        stats_text,
        transform=ax.transAxes,
        ha="left",
        va="top",
        bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
        fontsize=10,
        family="monospace",
    )

    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "reaction_time.png", dpi=300, bbox_inches="tight")
    plt.savefig(PLOTS_DIR / "reaction_time.pdf", bbox_inches="tight")
    print(f"Saved: {PLOTS_DIR / 'reaction_time.png'}")

    plt.close()


def generate_summary_statistics(df):
    """Generate and print summary statistics."""
    print("\n" + "=" * 60)
    print("Summary Statistics")
    print("=" * 60)

    # Experiment A
    exp_a = df[df["experiment"] == "A"]
    if not exp_a.empty:
        print("\nExperiment A: Crypto Overhead")
        print("-" * 60)
        for size in sorted(exp_a["payload_size_bytes"].unique()):
            size_data = exp_a[exp_a["payload_size_bytes"] == size]
            print(
                f"  {size/1024:.0f}KB: "
                f"Avg={size_data['avg_total_time_ms'].iloc[0]:.2f}ms, "
                f"Throughput={size_data['throughput_mbps'].iloc[0]:.2f} Mbps"
            )

    # Experiment B
    exp_b = df[df["experiment"] == "B"]
    if not exp_b.empty:
        print("\nExperiment B: End-to-End Throughput")
        print("-" * 60)
        for mode in exp_b["mode"].unique():
            mode_data = exp_b[exp_b["mode"] == mode]
            print(
                f"  {mode}: "
                f"{mode_data['effective_throughput_mbps'].iloc[0]:.2f} Mbps, "
                f"Time={mode_data['elapsed_time_seconds'].iloc[0]:.2f}s"
            )

    # Experiment C
    exp_c = df[df["experiment"] == "C"]
    exp_c_valid = exp_c[exp_c["reaction_time_ms"].notna()]
    if not exp_c_valid.empty:
        print("\nExperiment C: Adaptive Response Time")
        print("-" * 60)
        print(
            f"  Mean Reaction Time: {exp_c_valid['reaction_time_ms'].mean():.2f}ms"
        )
        print(
            f"  Std Deviation: {exp_c_valid['reaction_time_ms'].std():.2f}ms"
        )
        print(f"  Samples: {len(exp_c_valid)}")


def main():
    """Generate all visualizations."""
    print("=" * 60)
    print("sushCore Benchmark Results Analysis")
    print("=" * 60)

    df = load_data()

    # Generate plots
    plot_crypto_overhead(df)
    plot_throughput_comparison(df)
    plot_reaction_time(df)

    # Print statistics
    generate_summary_statistics(df)

    print("\n" + "=" * 60)
    print("All visualizations generated successfully!")
    print(f"Output directory: {PLOTS_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()

