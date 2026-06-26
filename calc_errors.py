"""
Count syntactic and semantic error iterations from run log files under an experiment folder.

Each iteration in a log file has a status: 'syntactic_error', 'semantic_error', or 'passed'.
Semantic errors also contain individual per-file failure entries.

Usage:
    python calc_errors.py <experiment_folder>

Example:
    python calc_errors.py generated_rego/ablation_no_history
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


def find_log_files(root: Path) -> list[Path]:
    return sorted(root.rglob("logs/*.json"))


def extract_cwe(path: Path) -> str:
    m = re.search(r"(cwe_\d+)", path.stem)
    return m.group(1) if m else "unknown"


def count_errors(log_files: list[Path]) -> tuple[dict, dict, list]:
    """
    Returns:
        per_cwe: {cwe: {syntactic, semantic, passed, semantic_file_failures}}
        totals:  same structure summed across all CWEs
        skipped: list of (path, exception) for unreadable files
    """
    per_cwe: dict[str, dict] = defaultdict(lambda: {
        "syntactic": 0, "semantic": 0, "passed": 0, "semantic_file_failures": 0
    })
    totals = {"syntactic": 0, "semantic": 0, "passed": 0, "semantic_file_failures": 0}
    skipped = []

    for path in log_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cwe = extract_cwe(path)
            for iteration in data.get("iterations", []):
                status = iteration.get("status", "")
                if status == "syntactic_error":
                    per_cwe[cwe]["syntactic"] += 1
                    totals["syntactic"] += 1
                elif status == "semantic_error":
                    per_cwe[cwe]["semantic"] += 1
                    totals["semantic"] += 1
                    per_cwe[cwe]["semantic_file_failures"] += len(iteration.get("errors", []))
                    totals["semantic_file_failures"] += len(iteration.get("errors", []))
                elif status == "passed":
                    per_cwe[cwe]["passed"] += 1
                    totals["passed"] += 1
        except Exception as e:
            skipped.append((path, e))

    return per_cwe, totals, skipped


def main():
    parser = argparse.ArgumentParser(description="Count error iterations for an experiment run.")
    parser.add_argument("folder", type=Path, help="Experiment folder to scan (e.g. generated_rego/my_test)")
    args = parser.parse_args()

    root = args.folder
    if not root.exists():
        print(f"Error: folder not found: {root}")
        raise SystemExit(1)

    log_files = find_log_files(root)
    if not log_files:
        print(f"No log files found under: {root}")
        raise SystemExit(1)

    per_cwe, totals, skipped = count_errors(log_files)

    print(f"Experiment folder : {root}")
    print(f"Log files found   : {len(log_files)}")
    if skipped:
        print(f"Skipped (errors)  : {len(skipped)}")
    print()

    cwe_col = 12
    print(f"{'CWE':<{cwe_col}}  {'Syntactic':>10}  {'Semantic':>9}  {'Passed':>7}  {'Total iters':>12}  {'Sem. file fails':>15}")
    print("-" * (cwe_col + 10 + 9 + 7 + 12 + 15 + 12))
    for cwe in sorted(per_cwe):
        d = per_cwe[cwe]
        total_iters = d["syntactic"] + d["semantic"] + d["passed"]
        print(f"{cwe:<{cwe_col}}  {d['syntactic']:>10}  {d['semantic']:>9}  {d['passed']:>7}  {total_iters:>12}  {d['semantic_file_failures']:>15}")

    print("-" * (cwe_col + 10 + 9 + 7 + 12 + 15 + 12))
    total_iters = totals["syntactic"] + totals["semantic"] + totals["passed"]
    print(f"{'TOTAL':<{cwe_col}}  {totals['syntactic']:>10}  {totals['semantic']:>9}  {totals['passed']:>7}  {total_iters:>12}  {totals['semantic_file_failures']:>15}")


if __name__ == "__main__":
    main()
