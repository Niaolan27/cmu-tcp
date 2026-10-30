#!/usr/bin/env python3
"""Plots a loss sweep from tests/loss_sweep.py: throughput against 1/sqrt(p),
with a least-squares line, and prints the fit and the Pearson correlation
coefficient.

    python3 tests/plot_loss_sweep.py loss_sweep.csv --out loss_sweep.png

Runs that didn't finish or whose hashes didn't match are left out and listed.
"""

import argparse
import csv
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
MEASURED = "#2a78d6"
FIT = "#eb6834"


def load(path):
    """Returns (loss percentages, throughputs in Mbps) for good runs, and the
    rows that were left out."""
    losses, mbps, skipped = [], [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["throughput_mbps"] and row["hash_ok"] == "True":
                losses.append(float(row["loss_pct"]))
                mbps.append(float(row["throughput_mbps"]))
            else:
                skipped.append(row)
    return np.array(losses), np.array(mbps), skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv")
    parser.add_argument("--out", default="loss_sweep.png")
    args = parser.parse_args()

    losses, mbps, skipped = load(args.csv)
    x = 1 / np.sqrt(losses / 100)
    slope, intercept = np.polyfit(x, mbps, 1)
    through_origin = np.sum(x * mbps) / np.sum(x * x)
    r = np.corrcoef(x, mbps)[0, 1]

    by_loss = defaultdict(list)
    for loss, value in zip(losses, mbps):
        by_loss[loss].append(value)
    print(
        f"{'p':>6}  {'1/sqrt(p)':>9}  {'runs':>4}  {'mean Mbps':>9}  "
        f"{'std':>6}"
    )
    for loss in sorted(by_loss):
        values = np.array(by_loss[loss])
        std = values.std(ddof=1) if len(values) > 1 else 0
        print(
            f"{loss:5g}%  {1 / np.sqrt(loss / 100):9.2f}  {len(values):4d}  "
            f"{values.mean():9.3f}  {std:6.3f}"
        )
    print(
        f"\nLeast squares:   throughput = {slope:.4f} * (1/sqrt(p)) "
        f"{'+' if intercept >= 0 else '-'} {abs(intercept):.4f} Mbps"
    )
    print(f"  C (slope) = {slope:.4f} Mbps")
    print(f"Through origin:  C = {through_origin:.4f} Mbps")
    print(f"Pearson r = {r:.4f}  (n = {len(x)} runs)")
    for row in skipped:
        print(
            f"Left out: p={row['loss_pct']}% run {row['run']} "
            f"(seconds={row['seconds'] or 'none'}, hash_ok={row['hash_ok']})"
        )

    means = sorted(
        (1 / np.sqrt(loss / 100), np.mean(v)) for loss, v in by_loss.items()
    )
    mean_x, mean_y = zip(*means)

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.size": 10,
            "text.color": INK,
            "axes.labelcolor": INK_SECONDARY,
            "xtick.color": INK_MUTED,
            "ytick.color": INK_MUTED,
        }
    )
    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    ax.scatter(
        x,
        mbps,
        s=28,
        color=MEASURED,
        alpha=0.35,
        edgecolors=SURFACE,
        linewidths=1,
        zorder=3,
        label="One run",
    )
    ax.plot(
        mean_x,
        mean_y,
        color=MEASURED,
        linewidth=2,
        marker="o",
        markersize=6,
        markeredgecolor=SURFACE,
        markeredgewidth=1.5,
        solid_capstyle="round",
        solid_joinstyle="round",
        zorder=4,
        label="Mean of runs at each p",
    )
    fit_x = np.array([0, x.max() * 1.03])
    ax.plot(
        fit_x,
        slope * fit_x + intercept,
        color=FIT,
        linewidth=2,
        solid_capstyle="round",
        zorder=2,
        label=f"Least-squares fit (C = {slope:.3f} Mbps)",
    )

    ax.set_xlim(0, x.max() * 1.05)
    ax.set_ylim(0, max(mbps.max(), (slope * fit_x + intercept).max()) * 1.1)
    ax.set_xlabel("1/√p   (the loss probability p is marked along the top)")
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title(
        "Throughput against 1/√p  (5 Mbps, 40 ms RTT, loss on "
        "data packets only)",
        loc="left",
        color=INK,
        fontsize=11,
    )
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
    ax.tick_params(length=0)

    # The loss rates themselves, along the top, so points map back to p.
    top = ax.secondary_xaxis("top")
    top.set_xticks([1 / np.sqrt(loss / 100) for loss in sorted(by_loss)])
    top.set_xticklabels([f"{loss:g}%" for loss in sorted(by_loss)])
    top.tick_params(length=0, colors=INK_MUTED, labelsize=8)
    top.spines["top"].set_visible(False)

    ax.text(
        0.98,
        0.04,
        f"Pearson r = {r:.3f}   n = {len(x)} runs",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        color=INK_SECONDARY,
        fontsize=9,
    )
    legend = ax.legend(loc="upper left", frameon=False, fontsize=9)
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)

    fig.tight_layout()
    fig.savefig(args.out, facecolor=SURFACE)
    print(f"\nPlot: {args.out}")


if __name__ == "__main__":
    main()
