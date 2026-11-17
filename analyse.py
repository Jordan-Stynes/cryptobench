"""Make the tables and plots for Parts 2-5 from one raw.csv.

Usage:
    python analyse.py results/run-1 "Linux Mint PC"
    python analyse.py results/run-2 "Windows laptop"

Reads <folder>/raw.csv and writes into the same folder:
    tables.md          the three tables (times in ms)
    kem.png            plot for Part 2
    signature.png      plot for Part 3
    aead.png           plot for Part 4
"""
import csv
import math
import os
import statistics
import sys

import matplotlib
matplotlib.use("Agg")                 # draw to files, no window needed
import matplotlib.pyplot as plt


KEM_ALGORITHMS = ["RSA-OAEP-3072", "RSA-OAEP-7680", "ECDH-P-256", "ECDH-P-384",
                  "ECDH-P-521", "X25519", "ML-KEM-768", "ML-KEM-1024"]
SIG_ALGORITHMS = ["RSA-PSS-3072", "RSA-PSS-7680", "ECDSA-P-256", "ECDSA-P-384",
                  "ECDSA-P-521", "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
AEAD_ALGORITHMS = ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-GCM-SIV"]
MESSAGE_LENGTHS = [64, 1024, 16384, 1048576]


def load(path):
    """Read raw.csv into {(algorithm, operation, message_bytes): [ns, ns, ...]}, without run 0."""
    times = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["run"] == "0":          # run 0 is the warm-up: leave it out
                continue
            key = (row["algorithm"], row["operation"], int(row["message_bytes"]))
            times.setdefault(key, []).append(int(row["nanoseconds"]))
    return times


def median_iqr_ms(values_ns):
    """Median and IQR in milliseconds, using statistics.quantiles with n=4."""
    q1, q2, q3 = statistics.quantiles(values_ns, n=4)
    median = statistics.median(values_ns)
    return median / 1e6, (q3 - q1) / 1e6


def fmt(x):
    """Round to 3 significant figures, without scientific notation."""
    if x == 0:
        return "0"
    decimals = 2 - int(math.floor(math.log10(abs(x))))
    rounded = round(x, decimals)
    return f"{rounded:.{max(decimals, 0)}f}"


def make_table(title, algorithms, operations, times, message_lengths=None):
    """Return one Markdown table: a row per algorithm (and message length), Median and IQR per operation."""
    first = "| Algorithm | " + ("Message (B) | " if message_lengths else "")
    first += " | ".join(f"{op} median | {op} IQR" for op in operations) + " |"
    lines = [f"### {title}", "", first,
             "|" + " --- |" * (first.count("|") - 1)]
    for alg in algorithms:
        for length in (message_lengths or [0]):
            cells = [alg] + ([str(length)] if message_lengths else [])
            for op in operations:
                median, iqr = median_iqr_ms(times[(alg, op, length)])
                cells += [fmt(median), fmt(iqr)]
            lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def bar_plot(algorithms, operations, times, title, path):
    """Grouped bars of the medians: algorithms on the x-axis, a bar per operation, log time axis."""
    width = 0.8 / len(operations)
    fig, ax = plt.subplots(figsize=(11, 5))
    smallest = None
    for i, op in enumerate(operations):
        medians = [median_iqr_ms(times[(alg, op, 0)])[0] for alg in algorithms]
        positions = [x + (i - (len(operations) - 1) / 2) * width for x in range(len(algorithms))]
        ax.bar(positions, medians, width, label=op)
        smallest = min(medians) if smallest is None else min(smallest, min(medians))
    ax.set_yscale("log")
    ax.set_ylim(bottom=10 ** math.floor(math.log10(smallest)))   # start at a power of ten
    ax.set_xticks(range(len(algorithms)))
    ax.set_xticklabels(algorithms, rotation=30, ha="right")
    ax.set_ylabel("Median time (ms)")
    ax.set_xlabel("Algorithm")
    ax.set_title(title)
    ax.legend()
    ax.grid(axis="y", which="major", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def line_plot(times, title, path):
    """Median encrypt time against message length, a line per algorithm, both axes log."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for alg in AEAD_ALGORITHMS:
        medians = [median_iqr_ms(times[(alg, "encrypt", n)])[0] for n in MESSAGE_LENGTHS]
        ax.plot(MESSAGE_LENGTHS, medians, marker="o", label=alg)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(MESSAGE_LENGTHS)
    ax.set_xticklabels([str(n) for n in MESSAGE_LENGTHS])
    ax.set_xlabel("Message length (bytes)")
    ax.set_ylabel("Median encrypt time (ms)")
    ax.set_title(title)
    ax.legend()
    ax.grid(which="major", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    folder = sys.argv[1]               # e.g. results/run-1
    label = sys.argv[2]                # e.g. "Linux Mint PC"
    times = load(os.path.join(folder, "raw.csv"))

    tables = make_table(f"Key establishment ({label}), times in ms", KEM_ALGORITHMS,
                        ["keygen", "encapsulate", "decapsulate"], times)
    tables += "\n" + make_table(f"Digital signatures ({label}), times in ms", SIG_ALGORITHMS,
                                ["keygen", "sign", "verify"], times)
    tables += "\n" + make_table(f"Authenticated encryption ({label}), times in ms", AEAD_ALGORITHMS,
                                ["encrypt", "decrypt"], times, MESSAGE_LENGTHS)
    with open(os.path.join(folder, "tables.md"), "w") as f:
        f.write(tables)

    bar_plot(KEM_ALGORITHMS, ["keygen", "encapsulate", "decapsulate"], times,
             f"Key establishment: median times ({label})", os.path.join(folder, "kem.png"))
    bar_plot(SIG_ALGORITHMS, ["keygen", "sign", "verify"], times,
             f"Digital signatures: median times ({label})", os.path.join(folder, "signature.png"))
    line_plot(times, f"Authenticated encryption: median encrypt time ({label})",
              os.path.join(folder, "aead.png"))

    print("Wrote tables.md, kem.png, signature.png and aead.png to", folder)


if __name__ == "__main__":
    main()
