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


def _clean_managed_type_names(tool: GlitchTool | KICSTool, rows: list[tuple[str, str]]) -> None:
    """Remove previously deployed rules for all type names managed by this mapping."""
    for type_name in sorted({type_name for type_name, _ in rows}):
        tool.remove_rule(type_name)


def _candidate_file_names(rego_file: str) -> list[str]:
    """Build candidate filenames (supports cwe-<id>.rego and cwe_<id>.rego)."""
    name = Path(rego_file).name
    candidates = [name]
    match = re.fullmatch(r"cwe-(\d+)\.rego", name.lower())
    if match:
        candidates.append(f"cwe_{match.group(1)}.rego")
    return list(dict.fromkeys(candidates))


def _resolve_rego_path(rules_dir: Path, rego_file: str) -> Path:
    """Resolve a mapping rego path relative to rules_dir with robust fallback."""
    rego_path = Path(rego_file)
    if rego_path.is_absolute():
        if rego_path.exists() and rego_path.is_file():
            return rego_path
        raise FileNotFoundError(f"Mapped absolute rego file not found: {rego_path}")

    # Try direct relative path first.
    direct = (rules_dir / rego_path).resolve()
    if direct.exists() and direct.is_file():
        return direct

    # Try alternative filename variants in rules_dir (e.g., cwe-250.rego -> cwe_250.rego).
    for candidate_name in _candidate_file_names(rego_file):
        candidate = (rules_dir / candidate_name).resolve()
        if candidate.exists() and candidate.is_file():
            return candidate

    # Recursive lookup under rules_dir for candidate file names.
    recursive_matches: list[Path] = []
    for candidate_name in _candidate_file_names(rego_file):
        recursive_matches.extend(p.resolve() for p in rules_dir.rglob(candidate_name) if p.is_file())
    recursive_matches = list(dict.fromkeys(recursive_matches))

    if len(recursive_matches) == 1:
        return recursive_matches[0]
    if len(recursive_matches) > 1:
        preview = "\n".join(f"  - {p}" for p in recursive_matches[:10])
        raise FileNotFoundError(
            "Ambiguous mapped rego file lookup for "
            f"'{rego_file}' under {rules_dir}. Found {len(recursive_matches)} matches:\n"
            f"{preview}\n"
            "Use a more specific --rules-dir (for example a single run folder) or set an explicit path in mapping."
        )

    raise FileNotFoundError(
        f"Mapped rego file not found for '{rego_file}' under {rules_dir}. "
        "Tried direct path, alternate cwe naming, and recursive lookup."
    )


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
        "--rules-dir",
        required=True,
        help="Directory containing .rego files referenced by the mapping file.",
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
        help=(
            "Project base directory for cwe2rego. "
            "Defaults to the folder containing this script."
        ),
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
    rules_dir = Path(args.rules_dir).expanduser().resolve()
    mapping_path = Path(args.mapping).expanduser().resolve()

    if not rules_dir.exists() or not rules_dir.is_dir():
        parser.error(f"--rules-dir does not exist or is not a directory: {rules_dir}")
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

    _clean_managed_type_names(tool, all_rows)

    written = 0
    for type_name, rego_file in rows:
        rego_path = _resolve_rego_path(rules_dir, rego_file)

        rego_content = rego_path.read_text(encoding="utf-8")
        tool.write_rule(type_name, rego_content)
        written += 1
        print(f"Wrote {label} rule for '{type_name}' from {rego_path}")

    print(f"Completed: wrote {written} {label} rule file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
