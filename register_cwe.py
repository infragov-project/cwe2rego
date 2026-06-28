"""Register a new CWE in all required system locations.

Checks each location before writing; skips steps already done.
Uses prompt_data/cwe_api.py to download the CWE JSON if needed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from prompt_data.cwe_api import get_cwe_weakness


BASE_DIR = Path(__file__).resolve().parent
CWE_DIR = BASE_DIR / "prompt_data" / "cwes"
KICS_MAPPING = BASE_DIR / "kics_rego_mapping.json"
GLITCH_MAPPING = BASE_DIR / "glitch_rego_mapping.json"
RUN_SCRIPT = BASE_DIR / "run_all_cwes.sh"
EXAMPLES_DIR = BASE_DIR / "validation" / "examples"


def _ensure_cwe_json(cwe: str) -> None:
    target = CWE_DIR / f"CWE-{cwe}.json"
    if target.exists():
        print(f"[skip] CWE JSON already exists: {target.relative_to(BASE_DIR)}")
        return
    print(f"[fetch] Downloading CWE-{cwe} from MITRE API...")
    data = get_cwe_weakness(int(cwe))
    CWE_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=4), encoding="utf-8")
    print(f"[ok]   Saved {target.relative_to(BASE_DIR)}")


def _update_json_mapping(mapping_path: Path, cwe: str, type_name: str) -> None:
    rego_file = f"cwe_{cwe}.rego"
    entries: list[dict] = json.loads(mapping_path.read_text(encoding="utf-8"))

    for entry in entries:
        if entry.get("rego_file") == rego_file and entry.get("type_name") == type_name:
            print(f"[skip] {mapping_path.name}: entry already present (type={type_name}, rego={rego_file})")
            return
        if entry.get("rego_file") == rego_file:
            existing_type = entry.get("type_name")
            print(
                f"[error] {mapping_path.name}: '{rego_file}' already mapped to type '{existing_type}'. "
                f"Remove the existing entry first if you intended to change it.",
                file=sys.stderr,
            )
            sys.exit(1)

    shared = [e.get("rego_file") for e in entries if e.get("type_name") == type_name]
    if shared:
        print(f"[info]  {mapping_path.name}: type '{type_name}' is already used by {shared} — sharing is allowed")

    entries.append({"type_name": type_name, "rego_file": rego_file})
    mapping_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    print(f"[ok]   {mapping_path.name}: added entry (type={type_name}, rego={rego_file})")


def _update_run_script(cwe: str, type_name: str) -> None:
    text = RUN_SCRIPT.read_text(encoding="utf-8")

    existing = re.search(rf'^\s*\[{re.escape(cwe)}\]\s*=\s*"[^"]*"', text, re.MULTILINE)
    if existing:
        print(f"[skip] run_all_cwes.sh: CWE-{cwe} already mapped ({existing.group().strip()})")
        return

    updated, count = re.subn(
        r'(declare\s+-A\s+TYPE_BY_CWE\s*=\s*\(.*?)\)',
        rf'\1    [{cwe}]="{type_name}"\n)',
        text,
        count=1,
        flags=re.DOTALL,
    )
    if count == 0:
        print("[warn] run_all_cwes.sh: could not locate TYPE_BY_CWE — edit manually", file=sys.stderr)
        return

    RUN_SCRIPT.write_text(updated, encoding="utf-8")
    print(f"[ok]   run_all_cwes.sh: added [{cwe}]=\"{type_name}\"")


def _check_examples(type_name: str) -> None:
    examples_path = EXAMPLES_DIR / type_name
    if examples_path.exists():
        print(f"[ok]   Semantic examples directory exists: {examples_path.relative_to(BASE_DIR)}")
    else:
        print(
            f"[warn] No semantic examples directory found for type '{type_name}'.\n"
            f"       Expected: {examples_path.relative_to(BASE_DIR)}\n"
            f"       Create it with IaC files + a manifest JSON, or pass --use-llm-examples when running."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a new CWE in the cwe2rego pipeline.")
    parser.add_argument("--cwe", required=True, help="CWE number (e.g. 732)")
    parser.add_argument("--type-name", required=True, help="Rule type name (e.g. sec_weak_perm)")
    parser.add_argument(
        "--mapping",
        choices=["both", "kics", "glitch"],
        default="both",
        help="Which JSON mapping file(s) to update (default: both)",
    )
    args = parser.parse_args()

    if not args.cwe.isdigit():
        parser.error("--cwe must be a numeric CWE identifier")

    cwe = args.cwe.lstrip("0") or "0"
    type_name = args.type_name

    print(f"\nRegistering CWE-{cwe} → '{type_name}'\n")

    _ensure_cwe_json(cwe)

    if args.mapping in ("both", "glitch"):
        _update_json_mapping(GLITCH_MAPPING, cwe, type_name)
    if args.mapping in ("both", "kics"):
        _update_json_mapping(KICS_MAPPING, cwe, type_name)

    _update_run_script(cwe, type_name)
    _check_examples(type_name)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
