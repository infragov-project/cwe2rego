#!/usr/bin/env python3
"""Calculate extension_examples_test run costs from OpenRouter activity CSV.

Rules:
- Only logs under generated_rego/extension_examples_test are considered.
- For Claude Sonnet logs, only run_id == run_002 is included.
- Requests are matched by model compatibility and request timestamp within
  [run_started_at_utc, ended_at_utc].
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import Iterable, Optional


@dataclass(frozen=True)
class RunWindow:
    log_path: Path
    run_id: str
    cwe: str
    model_used: str
    start_utc: datetime
    end_utc: datetime


@dataclass(frozen=True)
class RequestRow:
    generation_id: str
    created_at_utc: datetime
    model_permaslug: str
    effective_cost: float


def _request_matches_window(req: RequestRow, window: RunWindow) -> bool:
    return _models_match(window.model_used, req.model_permaslug) and (
        window.start_utc <= req.created_at_utc <= window.end_utc
    )


def _parse_iso_utc(value: str) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_csv_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    # OpenRouter CSV uses "YYYY-MM-DD HH:MM:SS.mmm" (UTC).
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_overlap_timestamp(value: str) -> Optional[datetime]:
    return _parse_iso_utc(value)


def _safe_float(value: str, default: float = 0.0) -> float:
    if value is None:
        return default
    text = str(value).strip()
    if text == "":
        return default
    try:
        return float(text)
    except ValueError:
        return default


def _model_tokens(model_name: str) -> tuple[str, set[str]]:
    model_name = (model_name or "").strip().lower()
    if "/" in model_name:
        provider, name = model_name.split("/", 1)
    else:
        provider, name = "", model_name

    # Remove date-like suffix chunks and split into semantic tokens.
    chunks = [c for c in re.split(r"[-_]", name) if c]
    tokens: set[str] = set()
    for chunk in chunks:
        if re.fullmatch(r"\d{6,}", chunk):
            continue
        tokens.add(chunk)

    return provider, tokens


def _models_match(log_model: str, csv_model: str) -> bool:
    log_provider, log_tokens = _model_tokens(log_model)
    csv_provider, csv_tokens = _model_tokens(csv_model)

    if log_provider and csv_provider and log_provider != csv_provider:
        return False

    if not log_tokens or not csv_tokens:
        return False

    # Log model should be a subset of CSV model after normalization.
    return log_tokens.issubset(csv_tokens)


def _load_run_windows(repo_root: Path, experiment_name: str) -> list[RunWindow]:
    logs_root = repo_root / "generated_rego" / experiment_name
    windows: list[RunWindow] = []

    for path in sorted(logs_root.glob("**/logs/*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        run_id = str(data.get("run_id") or "")
        cwe = str(data.get("cwe") or "")
        model_used = str(data.get("model_used") or "")

        # User requirement: for extension_examples_test + Claude Sonnet, only include run_002.
        if (
            experiment_name == "extension_examples_test"
            and "claude-sonnet-4.6" in model_used.lower()
            and run_id != "run_002"
        ):
            continue

        start = _parse_iso_utc(data.get("run_started_at_utc"))
        end = _parse_iso_utc((data.get("result") or {}).get("ended_at_utc") or data.get("ended_at_utc"))

        if start is None or end is None or end <= start:
            continue

        windows.append(
            RunWindow(
                log_path=path,
                run_id=run_id,
                cwe=cwe,
                model_used=model_used,
                start_utc=start,
                end_utc=end,
            )
        )

    return windows


def _iter_requests(csv_path: Path) -> Iterable[RequestRow]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"generation_id", "created_at", "cost_total", "model_permaslug"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(
                "CSV schema mismatch: expected headers generation_id, created_at, cost_total, model_permaslug"
            )

        for row in reader:
            created = _parse_csv_timestamp(row.get("created_at", ""))
            if created is None:
                continue
            cost_total = _safe_float(row.get("cost_total"))
            byok_usage_inference = _safe_float(row.get("byok_usage_inference"))
            # OpenRouter may record provider charges in byok_usage_inference while
            # leaving cost_total as 0. Prefer cost_total when present, otherwise fallback.
            effective_cost = cost_total if cost_total > 0 else byok_usage_inference

            yield RequestRow(
                generation_id=str(row.get("generation_id") or ""),
                created_at_utc=created,
                model_permaslug=str(row.get("model_permaslug") or ""),
                effective_cost=effective_cost,
            )


def _write_per_run_csv(output_path: Path, rows: list[dict[str, str]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "run_id",
        "cwe",
        "model_used",
        "matched_requests",
        "matched_cost_total",
        "log_file",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _load_overlap_intervals(overlap_csv: Path) -> dict[tuple[str, str], list[tuple[datetime, datetime]]]:
    intervals: dict[tuple[str, str], list[tuple[datetime, datetime]]] = defaultdict(list)
    if not overlap_csv.exists():
        return intervals

    with overlap_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {
            "left_experiment",
            "left_run_id",
            "left_smell",
            "right_experiment",
            "right_run_id",
            "right_smell",
            "overlap_start_utc",
            "overlap_end_utc",
        }
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            return intervals

        for row in reader:
            start = _parse_overlap_timestamp(row.get("overlap_start_utc", ""))
            end = _parse_overlap_timestamp(row.get("overlap_end_utc", ""))
            if start is None or end is None or end <= start:
                continue

            if row.get("left_experiment") == "extension_examples_test":
                key = (str(row.get("left_run_id") or ""), str(row.get("left_smell") or ""))
                intervals[key].append((start, end))

            if row.get("right_experiment") == "extension_examples_test":
                key = (str(row.get("right_run_id") or ""), str(row.get("right_smell") or ""))
                intervals[key].append((start, end))

    return intervals


def _load_overlap_run_keys(overlap_csv: Path) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if not overlap_csv.exists():
        return keys

    with overlap_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {
            "left_experiment",
            "left_run_id",
            "left_smell",
            "right_experiment",
            "right_run_id",
            "right_smell",
        }
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            return keys

        for row in reader:
            if row.get("left_experiment") == "extension_examples_test":
                keys.add((str(row.get("left_run_id") or ""), str(row.get("left_smell") or "")))
            if row.get("right_experiment") == "extension_examples_test":
                keys.add((str(row.get("right_run_id") or ""), str(row.get("right_smell") or "")))

    return keys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Calculate extension_examples_test run costs")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root path",
    )
    parser.add_argument(
        "--requests-csv",
        default=str(Path(__file__).resolve().parent / "openrouter_activity_2026-03-23_extension_examples_models.csv"),
        help="OpenRouter activity CSV path",
    )
    parser.add_argument(
        "--output-csv",
        default=str(Path(__file__).resolve().parent / "extension_examples_run_costs.csv"),
        help="Per-run cost output CSV path",
    )
    parser.add_argument(
        "--include-overlaps",
        action="store_true",
        help=(
            "Include requests that are ambiguous due to overlapping windows with kics_extension_test. "
            "Default behavior excludes these requests."
        ),
    )
    parser.add_argument(
        "--overlap-csv",
        default=str(Path(__file__).resolve().parent / "run_log_overlaps.csv"),
        help=(
            "Overlap CSV generated by find_run_log_overlaps.py. "
            "When present, overlap exclusion uses these intervals for consistency."
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    requests_csv = Path(args.requests_csv).expanduser().resolve()
    output_csv = Path(args.output_csv).expanduser().resolve()
    overlap_csv = Path(args.overlap_csv).expanduser().resolve()

    extension_windows = _load_run_windows(repo_root, "extension_examples_test")
    if not extension_windows:
        print("No eligible run windows found.")
        return 1

    overlap_run_keys = _load_overlap_run_keys(overlap_csv)

    if args.include_overlaps:
        active_windows = extension_windows
        excluded_windows: list[RunWindow] = []
    else:
        active_windows = [
            w for w in extension_windows if (w.run_id, w.cwe) not in overlap_run_keys
        ]
        excluded_windows = [
            w for w in extension_windows if (w.run_id, w.cwe) in overlap_run_keys
        ]

    if not active_windows:
        print("No eligible non-overlapping run windows found.")
        return 1

    request_rows = list(_iter_requests(requests_csv))

    per_run: list[dict[str, str]] = []
    grand_total = 0.0
    grand_requests = 0
    skipped_multi_extension = 0

    run_totals = {
        idx: {"cost": 0.0, "requests": 0}
        for idx in range(len(active_windows))
    }

    for req in request_rows:
        extension_matches = [
            idx
            for idx, window in enumerate(active_windows)
            if _request_matches_window(req, window)
        ]
        if not extension_matches:
            continue

        # Ambiguous inside extension itself.
        if len(extension_matches) > 1:
            skipped_multi_extension += 1
            continue

        target = extension_matches[0]
        run_totals[target]["cost"] += req.effective_cost
        run_totals[target]["requests"] += 1

    for idx, window in enumerate(active_windows):
        matched_cost = run_totals[idx]["cost"]
        matched_requests = run_totals[idx]["requests"]

        grand_total += matched_cost
        grand_requests += matched_requests

        per_run.append(
            {
                "run_id": window.run_id,
                "cwe": window.cwe,
                "model_used": window.model_used,
                "matched_requests": str(matched_requests),
                "matched_cost_total": f"{matched_cost:.6f}",
                "log_file": str(window.log_path),
            }
        )

    _write_per_run_csv(output_csv, per_run)

    print(f"Eligible extension run windows (raw): {len(extension_windows)}")
    print(f"Excluded overlapping run windows: {len(excluded_windows)}")
    print(f"Costed run windows: {len(active_windows)}")
    print(f"Overlap CSV used: {overlap_csv if overlap_csv.exists() else 'not found (dynamic fallback only)'}")
    print(f"Requests scanned: {len(request_rows)}")
    print(f"Matched requests: {grand_requests}")
    print(f"Skipped multi-extension ambiguous requests: {skipped_multi_extension}")
    print(f"Total extension_examples_test cost (Claude only run_002): {grand_total:.6f}")
    print(f"Per-run output: {output_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
