"""
Report at which iteration rules were created, from run log files under an experiment folder.

The experiment folder is expected to contain one folder per model, each with
runs/run_XXX/logs/*.json. Results are shown per model and aggregated (Total).

Every log file is one sample and the iteration is the one inside that run.
Averages only consider rules that were created (failed runs are left out).

A box plot of the same data is saved next to this script.

Usage:
    python calc_iterations.py <experiment_folder>

Example:
    python calc_iterations.py generated_rego/complete_pipeline_test
"""

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

TOTAL = "Total"
PLOT_PATH = Path(__file__).resolve().parent / "iterations_boxplot.png"

# names shown in the plot, by log folder name (folders not listed keep their name)
DISPLAY_NAMES = {
    "claude-sonnet-4-6": "Claude Sonnet 4.6",
    "mimo-v2.5-pro": "MiMo-V2.5-Pro",
    "kimi-k2.5": "Kimi K2.5",
}


def find_log_files(root: Path) -> list[Path]:
    return sorted(root.rglob("logs/*.json"))


def load_records(root: Path, log_files: list[Path]) -> tuple[list[dict], list]:
    """
    Returns:
        records: one dict per log {model, passed, attempts, max_attempts}
        skipped: list of (path, exception) for unreadable files
    """
    records = []
    skipped = []

    for path in log_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            result = data.get("result", {})
            attempts = result.get("attempts_used", len(data.get("iterations", [])))
            records.append({
                "model": path.relative_to(root).parts[0],
                "passed": bool(result.get("passed")),
                "attempts": attempts,
                "max_attempts": result.get("max_attempts", attempts),
            })
        except Exception as e:
            skipped.append((path, e))

    return records, skipped


def fmt(value: float) -> str:
    return f"{value:.2f}"


def stats_row(label: str, samples: int, values: list[int]) -> list[str]:
    created = len(values)
    rate = f"{100 * created / samples:.1f}%" if samples else "-"
    if not values:
        return [label, str(samples), str(created), rate, "-", "-", "-", "-", "-"]
    std = fmt(statistics.stdev(values)) if created > 1 else "-"
    return [
        label, str(samples), str(created), rate,
        fmt(statistics.mean(values)), fmt(statistics.median(values)),
        str(min(values)), str(max(values)), std,
    ]


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Prints an aligned table with a rule above the last row."""
    widths = [max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))]

    def line(cells: list[str]) -> str:
        first = str(cells[0]).ljust(widths[0])
        rest = [str(c).rjust(w) for c, w in zip(cells[1:], widths[1:])]
        return "  ".join([first] + rest)

    rule = "-" * len(line(headers))
    print(line(headers))
    print(rule)
    for i, row in enumerate(rows):
        if i == len(rows) - 1:
            print(rule)
        print(line(row))


def print_section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def print_summary(records: list[dict], models: list[str]) -> None:
    print_section("Iteration at which the rule was created, per run (each log is one sample)")
    headers = ["Model", "Logs", "Created", "Rate", "Mean", "Median", "Min", "Max", "Std"]
    rows = []
    for model in models + [TOTAL]:
        selected = [r for r in records if model in (r["model"], TOTAL)]
        values = [r["attempts"] for r in selected if r["passed"]]
        rows.append(stats_row(model, len(selected), values))
    print_table(headers, rows)


def print_iteration_counts(records: list[dict], models: list[str], max_iteration: int) -> None:
    columns = models + [TOTAL]

    counts = {c: defaultdict(int) for c in columns}
    for record in records:
        if record["passed"]:
            counts[record["model"]][record["attempts"]] += 1
            counts[TOTAL][record["attempts"]] += 1

    print_section("Rules created at each iteration")
    rows = [[str(i)] + [str(counts[c][i] or ".") for c in columns] for i in range(1, max_iteration + 1)]
    rows.append(["Created"] + [str(sum(counts[c].values())) for c in columns])
    print_table(["Iteration"] + columns, rows)


def plot_boxplot(records: list[dict], models: list[str], max_iteration: int, output: Path) -> None:
    """Box plot of the iteration at which the rule was created, per run (passed logs only)."""
    surface, ink, muted, grid = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
    model_color, total_color = "#2a78d6", "#8a8984"

    labels = models + [TOTAL]
    samples = [[r["attempts"] for r in records if r["passed"] and label in (r["model"], TOTAL)] for label in labels]
    logs = [sum(1 for r in records if label in (r["model"], TOTAL)) for label in labels]
    colors = [model_color] * len(models) + [total_color]

    fig, ax = plt.subplots(figsize=(8, 5), facecolor=surface)
    ax.set_facecolor(surface)

    boxes = ax.boxplot(
        samples, widths=0.5, patch_artist=True, showmeans=True, showfliers=False,
        medianprops={"color": ink, "linewidth": 2},
        meanprops={"marker": "D", "markerfacecolor": surface, "markeredgecolor": ink, "markersize": 7, "zorder": 4},
        whiskerprops={"color": muted}, capprops={"color": muted},
    )
    for box, color in zip(boxes["boxes"], colors):
        box.set(facecolor=color, alpha=0.35, edgecolor=color, linewidth=1.5)

    # every rule as a dot, spread sideways so equal iterations do not overlap
    for position, (values, color) in enumerate(zip(samples, colors), start=1):
        seen = defaultdict(int)
        for value in sorted(values):
            same = values.count(value)
            offset = (seen[value] - (same - 1) / 2) * 0.06
            seen[value] += 1
            ax.scatter(position + offset, value, s=28, color=color, edgecolor=surface, linewidth=0.8, zorder=3)

    ax.set_xticks(range(1, len(labels) + 1))
    ax.set_xticklabels([
        f"{DISPLAY_NAMES.get(label, label)}\n{len(v)} of {n} runs passed"
        for label, v, n in zip(labels, samples, logs)
    ])
    ax.set_ylim(0, max_iteration + 1)
    ax.set_yticks(range(0, max_iteration + 1, 2))
    ax.set_ylabel("Iteration at which the rule was created", color=muted)
    ax.yaxis.grid(True, color=grid, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=muted, length=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(grid)

    fig.text(
        0.01, 0.01,
        "Box: quartiles, line: median, diamond: mean, whiskers: up to 1.5 IQR, dots: one rule each. Failed runs are not included.",
        color=muted, fontsize=8,
    )
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(output, dpi=200, facecolor=surface)
    plt.close(fig)
    print(f"\nBox plot saved to {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Report at which iteration rules were created in an experiment."
    )
    parser.add_argument("experiment_folder", type=Path, help="Path to the experiment folder")
    args = parser.parse_args()

    root = args.experiment_folder
    if not root.is_dir():
        parser.error(f"'{root}' is not a directory")

    log_files = find_log_files(root)
    if not log_files:
        print(f"No log files found under '{root}'")
        return

    records, skipped = load_records(root, log_files)
    if not records:
        print(f"No readable log files found under '{root}'")
        return

    models = sorted({r["model"] for r in records})
    max_iteration = max(r["max_attempts"] for r in records)

    print(f"Experiment : {root}")
    print(f"Log files  : {len(log_files)}")
    print(f"Models     : {', '.join(models)}")

    print_summary(records, models)
    print_iteration_counts(records, models, max_iteration)
    plot_boxplot(records, models, max_iteration, PLOT_PATH)

    if skipped:
        print(f"\n  ({len(skipped)} file(s) skipped due to errors)")
        for path, err in skipped:
            print(f"    {path}: {err}")


if __name__ == "__main__":
    main()
