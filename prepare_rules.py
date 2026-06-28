"""Prepare analysis-tool rules from a batch of Rego rules.

This script installs/initializes either KICS or GLITCH support and writes
custom query rules using the selected analysis tool.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from llm_interaction.generation_logging import _extract_run_index, _list_run_indices
from validation.tools import GlitchTool, KICSTool


def _load_mapping(mapping_path: Path) -> list[tuple[str, str]]:
    """Load type_name -> rego_file mappings from JSON."""
    suffix = mapping_path.suffix.lower()
    if suffix == ".json":
        data = json.loads(mapping_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            rows = []
            for type_name, rego_file in data.items():
                rows.append((str(type_name).strip(), str(rego_file).strip()))
            return rows
        if isinstance(data, list):
            rows = []
            for idx, item in enumerate(data, 1):
                if not isinstance(item, dict):
                    raise ValueError(
                        f"Invalid JSON mapping item at index {idx}: expected object."
                    )
                type_name = str(item.get("type_name", "")).strip()
                rego_file = str(item.get("rego_file", "")).strip()
                rows.append((type_name, rego_file))
            return rows
        raise ValueError("JSON mapping must be either an object or a list of objects.")

    raise ValueError("Unsupported mapping file format. Use .json")


def _validate_rows(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Validate mapping rows and return only cleaned valid rows."""
    cleaned: list[tuple[str, str]] = []
    for idx, (type_name, rego_file) in enumerate(rows, 1):
        if not type_name:
            raise ValueError(f"Row {idx}: 'type_name' is required.")
        if not rego_file:
            raise ValueError(f"Row {idx}: 'rego_file' is required.")
        cleaned.append((type_name, rego_file))
    return cleaned


def _filter_rows(
    rows: list[tuple[str, str]],
    only_cwes: set[str] | None,
) -> list[tuple[str, str]]:
    """Filter rows by selected CWE numbers while preserving mapping order."""
    if only_cwes is None:
        return rows
    filtered = []
    for type_name, rego_file in rows:
        name = Path(rego_file).name.lower()
        match = re.fullmatch(r"cwe[-_](\d+)\.rego", name)
        if match:
            cwe = match.group(1)
            if cwe in only_cwes:
                filtered.append((type_name, rego_file))
    if not filtered:
        requested = ", ".join(sorted(only_cwes))
        raise ValueError(f"No rows matched --only-cwe selection: {requested}")
    return filtered


def _find_passing_rego(runs_dir: Path, rule_id: str) -> Path | None:
    """Return the rego path from the first run where result.passed is true, or None."""
    for run_index in _list_run_indices(runs_dir):
        run_dir = runs_dir / f"run_{run_index:03d}"
        rego_path = run_dir / f"{rule_id}.rego"
        if not rego_path.exists():
            continue
        log_dir = run_dir / "logs"
        if not log_dir.exists():
            continue
        log_files = list(log_dir.glob(f"{rule_id}__*.json"))
        if not log_files:
            continue
        log_data = json.loads(log_files[0].read_text(encoding="utf-8"))
        if log_data.get("result", {}).get("passed", False):
            return rego_path
    return None




def build_argument_parser(
    default_analysis_tool: str | None = None,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bulk write GLITCH or KICS rules from Rego rules and type_name mappings."
        )
    )
    parser.add_argument(
        "--analysis-tool",
        choices=["glitch", "kics"],
        required=True,
        help="Analysis tool to prepare.",
    )
    parser.add_argument(
        "--experiment-dir",
        required=True,
        help=(
            "Path to generated_rego/<experiment>/<model>. "
            "Scans its runs/ directory and deploys the rego from the first passing run per rule. "
            "Rules with no passing run are skipped."
        ),
    )
    parser.add_argument(
        "--mapping",
        required=True,
        help=(
            "JSON file describing type_name -> rego_file mapping. "
            "JSON supports either an object or a list with those keys."
        ),
    )
    parser.add_argument(
        "--base-dir",
        default=None,
        help="Project base directory. Defaults to the folder containing this script.",
    )
    parser.add_argument(
        "--only-cwe",
        action="append",
        default=[],
        nargs="+",
        metavar="CWE",
        help=(
            "Only prepare these CWE numbers. "
            "Examples: --only-cwe 284 1327 or --only-cwe 284 --only-cwe 1327."
        ),
    )
    return parser


def main(default_analysis_tool: str | None = None) -> int:
    parser = build_argument_parser(default_analysis_tool)
    argv = sys.argv[1:]
    if default_analysis_tool and "--analysis-tool" not in argv:
        argv = ["--analysis-tool", default_analysis_tool, *argv]
    args = parser.parse_args(argv)

    script_dir = Path(__file__).resolve().parent
    base_dir = (
        Path(args.base_dir).expanduser().resolve() if args.base_dir else script_dir
    )
    experiment_dir = Path(args.experiment_dir).expanduser().resolve()
    mapping_path = Path(args.mapping).expanduser().resolve()

    if not experiment_dir.exists() or not experiment_dir.is_dir():
        parser.error(f"--experiment-dir does not exist or is not a directory: {experiment_dir}")
    runs_dir = experiment_dir / "runs"
    if not runs_dir.exists():
        parser.error(f"No runs/ directory found under --experiment-dir: {experiment_dir}")
    if not mapping_path.exists() or not mapping_path.is_file():
        parser.error(f"--mapping does not exist or is not a file: {mapping_path}")

    all_rows = _validate_rows(_load_mapping(mapping_path))
    only_cwes = None
    if args.only_cwe:
        flat_cwes = [item for group in args.only_cwe for item in group]
        only_cwes = set(str(v).strip() for v in flat_cwes if str(v).strip())
    if only_cwes is not None and any(not cwe.isdigit() for cwe in only_cwes):
        parser.error("--only-cwe values must be numeric CWE identifiers")
    rows = _filter_rows(all_rows, only_cwes)

    if args.analysis_tool == "kics":
        KICSTool.install(base_dir)
        tool: GlitchTool | KICSTool = KICSTool(base_dir)
        label = "KICS"
    else:
        GlitchTool.install(base_dir)
        tool = GlitchTool(base_dir)
        label = "GLITCH"

    tool.clear_all_rules()

    written = 0
    skipped = 0
    for type_name, rego_file in rows:
        rule_id = Path(rego_file).stem
        rego_path = _find_passing_rego(runs_dir, rule_id)
        if rego_path is None and rule_id != type_name:
            rego_path = _find_passing_rego(runs_dir, type_name)
        if rego_path is None:
            print(f"Skipped '{type_name}' ({rule_id}): no passing run found.")
            skipped += 1
            continue

        rego_content = rego_path.read_text(encoding="utf-8")
        tool.write_rule(type_name, rego_content)
        written += 1
        print(f"Wrote {label} rule for '{type_name}' from {rego_path}")

    print(f"Completed: wrote {written} {label} rule file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
