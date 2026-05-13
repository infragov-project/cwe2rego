#!/usr/bin/env python3
"""Find overlapping run log intervals across experiment folders.

By default, this script scans JSON logs under:
- generated_rego/extension_examples_test
- generated_rego/kics_extension_test

It compares each log interval [run_started_at_utc, result.ended_at_utc]
against all others and writes overlaps to CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional


@dataclass(frozen=True)
class RunLog:
    log_path: Path
    experiment_name: str
    run_id: str
    cwe: str
    model_used: str
    start_utc: datetime
    end_utc: datetime

    @property
    def log_dir(self) -> str:
        return str(self.log_path.parent)

    @property
    def log_file(self) -> str:
        return self.log_path.name


@dataclass(frozen=True)
class Overlap:
    left: RunLog
    right: RunLog
    overlap_start_utc: datetime
    overlap_end_utc: datetime

    @property
    def overlap_seconds(self) -> float:
        return (self.overlap_end_utc - self.overlap_start_utc).total_seconds()


def _parse_iso_utc(value: str) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _find_log_files(repo_root: Path, experiments: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    base = repo_root / "generated_rego"
    for experiment in experiments:
        files.extend((base / experiment).glob("**/logs/*.json"))
    return sorted(set(files))


def _load_run_log(log_path: Path) -> Optional[RunLog]:
    try:
        data = json.loads(log_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    start_raw = data.get("run_started_at_utc")
    end_raw = (
        (data.get("result") or {}).get("ended_at_utc")
        or data.get("ended_at_utc")
    )

    start_utc = _parse_iso_utc(start_raw)
    end_utc = _parse_iso_utc(end_raw)

    if start_utc is None or end_utc is None or end_utc <= start_utc:
        return None

    return RunLog(
        log_path=log_path,
        experiment_name=str(data.get("experiment_name") or ""),
        run_id=str(data.get("run_id") or ""),
        cwe=str(data.get("cwe") or ""),
        model_used=str(data.get("model_used") or ""),
        start_utc=start_utc,
        end_utc=end_utc,
    )


def _find_overlaps(logs: list[RunLog], cross_experiment_only: bool) -> list[Overlap]:
    sorted_logs = sorted(logs, key=lambda item: item.start_utc)
    overlaps: list[Overlap] = []
    seen: set[tuple[str, str, str, str]] = set()

    for i, left in enumerate(sorted_logs):
        for j in range(i + 1, len(sorted_logs)):
            right = sorted_logs[j]

            # Because logs are sorted by start, no later item can overlap once this fails.
            if right.start_utc >= left.end_utc:
                break

            if cross_experiment_only and left.experiment_name == right.experiment_name:
                continue

            overlap_start = max(left.start_utc, right.start_utc)
            overlap_end = min(left.end_utc, right.end_utc)

            if overlap_start < overlap_end:
                # Canonicalize pair ordering to avoid mirrored duplicates.
                left_key = str(left.log_path)
                right_key = str(right.log_path)
                if right_key < left_key:
                    left, right = right, left
                    left_key, right_key = right_key, left_key

                dedupe_key = (
                    left_key,
                    right_key,
                    overlap_start.isoformat(),
                    overlap_end.isoformat(),
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                overlaps.append(
                    Overlap(
                        left=left,
                        right=right,
                        overlap_start_utc=overlap_start,
                        overlap_end_utc=overlap_end,
                    )
                )

    return overlaps


def _write_overlaps_csv(output_path: Path, overlaps: list[Overlap]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "left_experiment",
        "left_directory",
        "left_file",
        "left_smell",
        "left_run_id",
        "left_start_utc",
        "left_end_utc",
        "right_experiment",
        "right_directory",
        "right_file",
        "right_smell",
        "right_run_id",
        "right_start_utc",
        "right_end_utc",
        "overlap_start_utc",
        "overlap_end_utc",
        "overlap_seconds",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in overlaps:
            writer.writerow(
                {
                    "left_experiment": item.left.experiment_name,
                    "left_directory": item.left.log_dir,
                    "left_file": item.left.log_file,
                    "left_smell": item.left.cwe,
                    "left_run_id": item.left.run_id,
                    "left_start_utc": item.left.start_utc.isoformat(),
                    "left_end_utc": item.left.end_utc.isoformat(),
                    "right_experiment": item.right.experiment_name,
                    "right_directory": item.right.log_dir,
                    "right_file": item.right.log_file,
                    "right_smell": item.right.cwe,
                    "right_run_id": item.right.run_id,
                    "right_start_utc": item.right.start_utc.isoformat(),
                    "right_end_utc": item.right.end_utc.isoformat(),
                    "overlap_start_utc": item.overlap_start_utc.isoformat(),
                    "overlap_end_utc": item.overlap_end_utc.isoformat(),
                    "overlap_seconds": f"{item.overlap_seconds:.3f}",
                }
            )


def _print_overlaps(overlaps: list[Overlap]) -> None:
    if not overlaps:
        print("No overlaps found.")
        return

    print("Overlaps (smell / run / file / overlap window):")
    for idx, item in enumerate(overlaps, start=1):
        print(
            f"{idx:>3}. "
            f"L[{item.left.experiment_name}] CWE-{item.left.cwe} {item.left.run_id} {item.left.log_file} "
            f"<-> R[{item.right.experiment_name}] CWE-{item.right.cwe} {item.right.run_id} {item.right.log_file} | "
            f"{item.overlap_start_utc.isoformat()} -> {item.overlap_end_utc.isoformat()} "
            f"({item.overlap_seconds:.3f}s)"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find overlapping run logs across generated_rego experiments"
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root directory (default: parent of this script's folder)",
    )
    parser.add_argument(
        "--experiments",
        nargs="+",
        default=["extension_examples_test", "kics_extension_test"],
        help="Experiment folders under generated_rego to scan",
    )
    parser.add_argument(
        "--cross-experiment-only",
        action="store_true",
        help="Only include overlaps where logs belong to different experiments",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parent / "run_log_overlaps.csv"),
        help="Output CSV path",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    repo_root = Path(args.repo_root).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    log_files = _find_log_files(repo_root, args.experiments)
    logs: list[RunLog] = []
    skipped = 0

    for file_path in log_files:
        loaded = _load_run_log(file_path)
        if loaded is None:
            skipped += 1
            continue
        logs.append(loaded)

    overlaps = _find_overlaps(logs, cross_experiment_only=bool(args.cross_experiment_only))
    _write_overlaps_csv(output_path, overlaps)

    print(f"Scanned log files: {len(log_files)}")
    print(f"Valid intervals: {len(logs)}")
    print(f"Skipped logs: {skipped}")
    print(f"Overlaps found: {len(overlaps)}")
    print(f"Output written to: {output_path}")
    _print_overlaps(overlaps)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
