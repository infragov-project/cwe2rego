#!/usr/bin/env python3
"""Compare generation logs for the same CWE across two experiment folders.

Reads JSON run logs produced under generated_rego/<experiment>/<model>/runs/<run_id>/logs/
and reports iterations, syntactic vs semantic failure counts, and final pass/fail for each side.

Example (compare two experiments):
  python cost/compare_extension_experiment_logs.py \\
    --left extension_norag_test --right extension_examples_test \\
    --model mimo-v2-flash --run run_001

Example (single experiment + model):
  python cost/compare_extension_experiment_logs.py \\
    --experiment extension_examples_test --model gpt-5.2-codex --run run_001
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class LogStats:
    cwe: str
    log_path: Path
    total_iterations: int
    syntactic_iterations: int
    semantic_iterations: int
    passed_iterations: int
    other_status_iterations: int
    error_records_syntactic: int
    error_records_semantic: int
    final_passed: Optional[bool]
    attempts_used: Optional[int]
    max_attempts: Optional[int]


_CWE_LOG_RE = re.compile(r"^cwe_(\d+)__model_.+__run_\d+\.json$")


def _parse_log(log_path: Path) -> Optional[LogStats]:
    try:
        data: dict[str, Any] = json.loads(log_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    cwe = str(data.get("cwe") or "").strip()
    m = _CWE_LOG_RE.match(log_path.name)
    if not cwe and m:
        cwe = m.group(1)
    if not cwe:
        return None

    iterations = data.get("iterations")
    if not isinstance(iterations, list):
        iterations = []

    syn_it = sem_it = pass_it = other_it = 0
    rec_syn = rec_sem = 0

    for it in iterations:
        if not isinstance(it, dict):
            other_it += 1
            continue
        status = it.get("status")
        if status == "syntactic_error":
            syn_it += 1
        elif status == "semantic_error":
            sem_it += 1
        elif status == "passed":
            pass_it += 1
        else:
            other_it += 1

        errs = it.get("errors")
        if isinstance(errs, list):
            for err in errs:
                if not isinstance(err, dict):
                    continue
                et = err.get("error_type")
                if et == "syntactic":
                    rec_syn += 1
                elif et == "semantic":
                    rec_sem += 1

    result = data.get("result")
    final_passed: Optional[bool] = None
    attempts_used: Optional[int] = None
    max_attempts: Optional[int] = None
    if isinstance(result, dict):
        if "passed" in result:
            final_passed = bool(result["passed"])
        au = result.get("attempts_used")
        if isinstance(au, int):
            attempts_used = au
        ma = result.get("max_attempts")
        if isinstance(ma, int):
            max_attempts = ma

    return LogStats(
        cwe=cwe,
        log_path=log_path,
        total_iterations=len(iterations),
        syntactic_iterations=syn_it,
        semantic_iterations=sem_it,
        passed_iterations=pass_it,
        other_status_iterations=other_it,
        error_records_syntactic=rec_syn,
        error_records_semantic=rec_sem,
        final_passed=final_passed,
        attempts_used=attempts_used,
        max_attempts=max_attempts,
    )


def _collect_logs(exp_root: Path) -> dict[str, Path]:
    """Map CWE id -> log path (one log per CWE: first path if duplicates)."""
    out: dict[str, Path] = {}
    for p in sorted(exp_root.glob("**/logs/cwe_*__model_*__run_*.json")):
        stats = _parse_log(p)
        if stats is None:
            continue
        out.setdefault(stats.cwe, p)
    return out


def _experiment_root(repo_root: Path, experiment: str, model: str, run_id: str) -> Path:
    return repo_root / "generated_rego" / experiment / model / "runs" / run_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (default: parent of cost/).",
    )
    parser.add_argument(
        "--experiment",
        default=None,
        metavar="NAME",
        help=(
            "Analyze only this experiment (with --model and --run). "
            "Omits --left/--right comparison."
        ),
    )
    parser.add_argument(
        "--left",
        default="extension_norag_test",
        help="Left experiment folder name under generated_rego/ (ignored if --experiment).",
    )
    parser.add_argument(
        "--right",
        default="extension_examples_test",
        help="Right experiment folder name under generated_rego/ (ignored if --experiment).",
    )
    parser.add_argument(
        "--model",
        default="mimo-v2-flash",
        help="Model subdirectory under the experiment.",
    )
    parser.add_argument(
        "--run",
        dest="run_id",
        default="run_001",
        help="Run id directory (e.g. run_001).",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional path to write a CSV table.",
    )
    args = parser.parse_args()
    repo_root: Path = args.repo_root.resolve()

    def fmt_pass(p: Optional[bool]) -> str:
        if p is True:
            return "yes"
        if p is False:
            return "no"
        return "?"

    if args.experiment:
        run_root = _experiment_root(repo_root, args.experiment, args.model, args.run_id)
        if not run_root.is_dir():
            print(f"Missing run directory: {run_root}", file=sys.stderr)
            return 1
        logs = _collect_logs(run_root)
        all_cwes = sorted(logs.keys(), key=int)
        rows: list[dict[str, Any]] = []
        for cwe in all_cwes:
            lp = logs[cwe]
            st = _parse_log(lp)
            assert st is not None
            au, ma = st.attempts_used, st.max_attempts
            rows.append(
                {
                    "cwe": cwe,
                    "iters": st.total_iterations,
                    "syn": st.syntactic_iterations,
                    "sem": st.semantic_iterations,
                    "err_rec_syn": st.error_records_syntactic,
                    "err_rec_sem": st.error_records_semantic,
                    "pass": fmt_pass(st.final_passed),
                    "attempts": (
                        f"{au}/{ma}"
                        if au is not None and ma is not None
                        else (str(au) if au is not None else "")
                    ),
                    "log": str(lp.relative_to(repo_root)),
                }
            )
        hdr = f"{'CWE':>5} | {'it syn sem pass':^18} | {'attempts':^8} | log (short)"
        print(
            f"Single run: {args.experiment} | model={args.model} run={args.run_id}\n"
            f"Root: {run_root}\n"
        )
        print(hdr)
        print("-" * len(hdr))
        for row in rows:
            short = Path(row["log"]).name
            print(
                f"{int(row['cwe']):5d} | "
                f"{row['iters']!s:>2} {row['syn']!s:>3} {row['sem']!s:>3} {row['pass']!s:>4} | "
                f"{str(row['attempts']):^8} | {short}"
            )
        print()
        print(
            "Columns: CWE | iterations, syntactic-fail iters, semantic-fail iters, passed | "
            "attempts_used/max | log file."
        )
        if args.csv:
            fieldnames = [
                "cwe",
                "iters",
                "syn",
                "sem",
                "err_rec_syn",
                "err_rec_sem",
                "pass",
                "attempts",
                "log",
            ]
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            with args.csv.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                w.writerows(rows)
            print(f"Wrote {args.csv}")
        return 0

    left_root = _experiment_root(repo_root, args.left, args.model, args.run_id)
    right_root = _experiment_root(repo_root, args.right, args.model, args.run_id)

    if not left_root.is_dir():
        print(f"Missing left run directory: {left_root}", file=sys.stderr)
        return 1
    if not right_root.is_dir():
        print(f"Missing right run directory: {right_root}", file=sys.stderr)
        return 1

    left_logs = _collect_logs(left_root)
    right_logs = _collect_logs(right_root)
    all_cwes = sorted(set(left_logs) | set(right_logs), key=int)

    rows = []
    for cwe in all_cwes:
        row: dict[str, Any] = {"cwe": cwe}
        for side, logs, label in (
            ("left", left_logs, args.left),
            ("right", right_logs, args.right),
        ):
            lp = logs.get(cwe)
            if lp is None:
                row[f"{side}_log"] = ""
                row[f"{side}_iters"] = ""
                row[f"{side}_syn"] = ""
                row[f"{side}_sem"] = ""
                row[f"{side}_err_rec_syn"] = ""
                row[f"{side}_err_rec_sem"] = ""
                row[f"{side}_pass"] = ""
                row[f"{side}_attempts"] = ""
                continue
            st = _parse_log(lp)
            assert st is not None
            row[f"{side}_log"] = str(lp.relative_to(repo_root))
            row[f"{side}_iters"] = st.total_iterations
            row[f"{side}_syn"] = st.syntactic_iterations
            row[f"{side}_sem"] = st.semantic_iterations
            row[f"{side}_err_rec_syn"] = st.error_records_syntactic
            row[f"{side}_err_rec_sem"] = st.error_records_semantic
            row[f"{side}_pass"] = fmt_pass(st.final_passed)
            au = st.attempts_used
            ma = st.max_attempts
            row[f"{side}_attempts"] = f"{au}/{ma}" if au is not None and ma is not None else (str(au) if au is not None else "")
        rows.append(row)

    # Console table (fixed-ish columns)
    hdr = (
        f"{'CWE':>5} | "
        f"{'L it syn sem pass':^22} | "
        f"{'R it syn sem pass':^22} | "
        f"L log (short)"
    )
    print(f"Compare {args.left} vs {args.right} | model={args.model} run={args.run_id}")
    print(f"Left root:  {left_root}")
    print(f"Right root: {right_root}")
    print()
    print(hdr)
    print("-" * len(hdr))
    for row in rows:
        li = row.get("left_iters", "")
        ls = row.get("left_syn", "")
        lm = row.get("left_sem", "")
        lp = row.get("left_pass", "")
        ri = row.get("right_iters", "")
        rs_ = row.get("right_syn", "")
        rm = row.get("right_sem", "")
        rp = row.get("right_pass", "")
        left_m = f"{li!s:>2} {ls!s:>3} {lm!s:>3} {lp!s:>4}" if li != "" else f"{'—':>22}"
        right_m = f"{ri!s:>2} {rs_!s:>3} {rm!s:>3} {rp!s:>4}" if ri != "" else f"{'—':>22}"
        lpth = row.get("left_log") or row.get("right_log") or ""
        short = Path(lpth).name if lpth else ""
        print(f"{int(row['cwe']):5d} | {left_m} | {right_m} | {short}")

    print()
    print(
        "Columns: CWE | L: iterations, syntactic-fail iterations, semantic-fail iterations, passed | "
        "R: same. For raw error-item counts use CSV (err_rec_syn / err_rec_sem)."
    )

    if args.csv:
        fieldnames = [
            "cwe",
            "left_iters",
            "left_syn",
            "left_sem",
            "left_err_rec_syn",
            "left_err_rec_sem",
            "left_pass",
            "left_attempts",
            "left_log",
            "right_iters",
            "right_syn",
            "right_sem",
            "right_err_rec_syn",
            "right_err_rec_sem",
            "right_pass",
            "right_attempts",
            "right_log",
        ]
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"Wrote {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
