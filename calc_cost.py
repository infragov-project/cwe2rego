"""
Calculate LLM cost from token counts stored in run log files under an experiment folder.
cache_read_tokens and cache_write_tokens are subsets of input_tokens, each billed at their own rate.
Prices are per 1M tokens.

Usage:
    python calc_cost.py <experiment_folder> [--input PRICE] [--cache-read PRICE] [--cache-write PRICE] [--output PRICE]

Example:
    python calc_cost.py generated_rego/no_semantic_check_test --input 0.435 --cache-read 0.0036 --cache-write 0.54375 --output 0.87
"""

import argparse
import json
import re
from pathlib import Path


def find_log_files(root: Path) -> list[Path]:
    return sorted(root.rglob("logs/*.json"))


def count_unique_rules(log_files: list[Path]) -> int:
    ids: set[str] = set()
    for path in log_files:
        m = re.search(r"(cwe_\d+)", path.stem)
        if m:
            ids.add(m.group(1))
    return len(ids)


def sum_tokens(log_files: list[Path]) -> tuple[dict, list]:
    totals = {
        "calls": 0,
        "input_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
    }
    skipped = []
    for path in log_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            usage = data.get("llm_usage", {})
            totals["calls"] += usage.get("calls", 0)
            totals["input_tokens"] += usage.get("input_tokens_total", 0)
            totals["cache_read_tokens"] += usage.get("cache_read_tokens_total", 0)
            totals["cache_write_tokens"] += usage.get("cache_write_tokens_total", 0)
            totals["output_tokens"] += usage.get("output_tokens_total", 0)
            totals["reasoning_tokens"] += usage.get("reasoning_tokens_total", 0)
        except Exception as e:
            skipped.append((path, e))
    return totals, skipped


def calc_cost(
    totals: dict,
    input_price: float,
    cache_read_price: float,
    cache_write_price: float,
    output_price: float,
) -> dict:
    # input_tokens includes cache_read and cache_write; subtract both for the fresh-input slice
    fresh_input = totals["input_tokens"] - totals["cache_read_tokens"] - totals["cache_write_tokens"]
    fresh_input = max(fresh_input, 0)
    input_cost = (fresh_input / 1_000_000) * input_price
    cache_read_cost = (totals["cache_read_tokens"] / 1_000_000) * cache_read_price
    cache_write_cost = (totals["cache_write_tokens"] / 1_000_000) * cache_write_price
    output_cost = (totals["output_tokens"] / 1_000_000) * output_price
    return {
        "fresh_input": fresh_input,
        "input_cost": input_cost,
        "cache_read_cost": cache_read_cost,
        "cache_write_cost": cache_write_cost,
        "output_cost": output_cost,
        "total": input_cost + cache_read_cost + cache_write_cost + output_cost,
    }


def main():
    parser = argparse.ArgumentParser(description="Calculate LLM cost for an experiment run.")
    parser.add_argument("folder", type=Path, help="Experiment folder to scan (e.g. generated_rego/my_test)")
    parser.add_argument("--input", type=float, default=0.435, metavar="PRICE", help="Fresh input token price per 1M (default: 0.435)")
    parser.add_argument("--cache-read", type=float, default=0.0036, metavar="PRICE", help="Cache read token price per 1M (default: 0.0036)")
    parser.add_argument("--cache-write", type=float, default=0.54375, metavar="PRICE", help="Cache write token price per 1M (default: 0.54375, i.e. 1.25x input default)")
    parser.add_argument("--output", type=float, default=0.87, metavar="PRICE", help="Output token price per 1M (default: 0.87)")
    args = parser.parse_args()

    root = args.folder
    if not root.exists():
        print(f"Error: folder not found: {root}")
        raise SystemExit(1)

    log_files = find_log_files(root)
    if not log_files:
        print(f"No log files found under: {root}")
        raise SystemExit(1)

    totals, skipped = sum_tokens(log_files)
    costs = calc_cost(totals, args.input, args.cache_read, args.cache_write, args.output)

    print(f"Experiment folder : {root}")
    print(f"Log files found   : {len(log_files)}  ({totals['calls']} LLM calls)")
    if skipped:
        print(f"Skipped (errors)  : {len(skipped)}")
    print()
    print(f"Token breakdown:")
    print(f"  Input (fresh)      : {costs['fresh_input']:>12,}  @ ${args.input}/1M       -> ${costs['input_cost']:.6f}")
    print(f"  Cache read         : {totals['cache_read_tokens']:>12,}  @ ${args.cache_read}/1M    -> ${costs['cache_read_cost']:.6f}")
    print(f"  Cache write        : {totals['cache_write_tokens']:>12,}  @ ${args.cache_write}/1M  -> ${costs['cache_write_cost']:.6f}")
    print(f"  Output             : {totals['output_tokens']:>12,}  @ ${args.output}/1M      -> ${costs['output_cost']:.6f}")
    if totals["reasoning_tokens"]:
        print(f"  Reasoning (info)   : {totals['reasoning_tokens']:>12,}")
    print()
    print(f"  Total cost         :                                        ${costs['total']:.6f}")
    num_rules = count_unique_rules(log_files)
    avg = costs["total"] / num_rules if num_rules else 0.0
    print(f"  Avg cost/rule      :                                        ${avg:.6f}  ({num_rules} rules)")


if __name__ == "__main__":
    main()
