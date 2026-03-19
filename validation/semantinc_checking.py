import csv
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

from click.testing import CliRunner

from validation.tools.base import AnalysisTool


def _load_examples(folder: Path, cwe_number: str) -> List[Dict[str, Any]]:
    manifest_path = folder / f"cwe-{cwe_number}.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"JSON manifest not found: {manifest_path}")

    with open(manifest_path, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "examples" in data:
        return data["examples"]
    raise ValueError("Unsupported manifest format; expected list or dict with 'examples'")


def _write_generated_examples(folder: Path, cwe_number: str, examples: List[Dict[str, Any]]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    manifest: List[Dict[str, Any]] = []

    for ex in examples:
        path = folder / ex["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ex.get("content", ""), encoding="utf-8")

        manifest_entry: Dict[str, Any] = {"file": ex["file"], "lines": ex["lines"]}
        manifest.append(manifest_entry)

    manifest_path = folder / f"cwe-{cwe_number}.json"
    manifest_path.write_text(json.dumps({"examples": manifest}, indent=2), encoding="utf-8")


def _resolve_static_examples_folder(examples_dir: Path, cwe_number: str) -> Path:
    """Resolve a static examples directory to the concrete CWE folder.

    Supported inputs:
    - Base directory containing CWE-<id>/ subfolders
    - Direct CWE folder containing cwe-<id>.json
    """
    manifest_name = f"cwe-{cwe_number}.json"
    cwe_subdir = examples_dir / f"CWE-{cwe_number}"

    if (examples_dir / manifest_name).exists():
        return examples_dir
    if (cwe_subdir / manifest_name).exists():
        return cwe_subdir

    if cwe_subdir.exists():
        return cwe_subdir
    return examples_dir


def _verify_examples(
    tool: AnalysisTool,
    runner: CliRunner,
    folder: Path,
    example: Dict[str, Any],
    type_name: str,
    csv_path: Path,
) -> Tuple[str, str, List[int], List[int], str] | None:
    """
    Verify a single example.

    Returns:
        Tuple of (ir_file, iac_language, missing_lines, false_positives, file_name)
        if validation fails, None if passes
    """
    file_name = example.get("file")
    if not file_name:
        raise ValueError("Example entry missing 'file'")

    script_path = folder / file_name
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    expected_lines = example.get("lines") or example.get("line")
    if isinstance(expected_lines, int):
        expected_lines = [expected_lines]
    if not expected_lines:
        raise ValueError(f"Missing expected lines for script: {script_path}")

    tech = tool.get_file_type(str(script_path))
    if tech is None:
        raise ValueError(f"Unsupported file type: {script_path}")

    unit_type = example.get("type") or "unknown"

    print(f"  Checking {script_path.name} (type: {unit_type}, expected lines: {expected_lines})")

    if csv_path.exists():
        csv_path.unlink()

    tool.run_lint(tech, unit_type, script_path, csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(f"{tool.name} did not produce CSV: {csv_path}")

    detected_lines: List[int] = []
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            error_type = (row.get("ERROR") or "").strip()
            line_value = (row.get("LINE") or "").strip()
            if error_type != type_name or not line_value:
                continue
            try:
                detected_lines.append(int(line_value))
            except ValueError:
                continue

    if csv_path.exists():
        csv_path.unlink()

    detected_set = set(detected_lines)
    expected_set = set(expected_lines)
    missing = [line for line in expected_lines if line not in detected_set]
    false_positives = [line for line in detected_lines if line not in expected_set]

    if missing or false_positives:
        ir = tool.extract_ir(str(script_path), unit_type)
        if missing:
            print(f"    ❌ Missing detections on lines: {missing}")
        if false_positives:
            print(f"    ❌ False positives on lines: {false_positives}")
        return (ir, tech, missing, false_positives, file_name)

    print(f"    ✅ All expected lines detected")
    return None


def prepare_semantic_examples(
    type_name: str,
    cwe_number: str,
    tool: Optional[AnalysisTool] = None,
    use_llm_examples: bool = False,
    cwe_text: Optional[str] = None,
    api_key: Optional[str] = None,
    examples_model: Optional[str] = None,
    model_directory: Optional[Path] = None,
    generated_examples_dir: Optional[Path] = None,
    target_technologies: Optional[List[str]] = None,
    static_examples_dir: Optional[Path] = None,
) -> Tuple[Path, List[Dict[str, Any]]]:
    """Prepare semantic-check examples once and return the folder and manifest entries."""
    if use_llm_examples:
        if not cwe_text:
            raise ValueError("cwe_text required when use_llm_examples is True")
        if tool is None:
            raise ValueError("tool required when use_llm_examples is True")

        from llm_interaction.example_generation import get_llm_examples

        examples = get_llm_examples(
            cwe_text=cwe_text,
            type_name=type_name,
            cwe_number=cwe_number,
            tool=tool,
            model_override=examples_model,
            api_key=api_key,
            target_technologies=target_technologies,
        )
        if generated_examples_dir is not None:
            folder = Path(generated_examples_dir)
        elif model_directory is not None:
            folder = Path(model_directory) / "generated_examples" / f"CWE-{cwe_number}"
        else:
            raise ValueError(
                "generated_examples_dir or model_directory required when use_llm_examples is True"
            )

        _write_generated_examples(folder, cwe_number, examples)
        print(f"  Generated {len(examples)} example(s) via LLM, saved to {folder}")
        return folder, examples

    if static_examples_dir is not None:
        folder = _resolve_static_examples_folder(Path(static_examples_dir), cwe_number)
    else:
        folder = Path(__file__).parent / "examples" / f"CWE-{cwe_number}"

    examples = _load_examples(folder, cwe_number)
    print(f"  Loaded {len(examples)} example(s) from {folder}")
    return folder, examples


def semantic_check(
    tool: AnalysisTool,
    rego_rule: str,
    type_name: str,
    cwe_number: str,
    examples_folder: Path,
    examples: List[Dict[str, Any]],
    technologies: Optional[List[str]] = None,
) -> List[Tuple[str, str, List[int], List[int], str]]:
    """
    Verify all examples for a CWE using a preloaded examples manifest.

    Args:
        tool: The analysis tool (e.g. GlitchTool) used to run lint and extract IR.
        rego_rule: The generated Rego rule content
        type_name: The smell code name (e.g., 'sec_hardcoded_secret')
        cwe_number: CWE number (e.g., "1327")
        examples_folder: Root folder where referenced example files live
        examples: Preloaded example manifest entries
        technologies: If set, only run semantic check for these techs (e.g. ["ansible"]). None = all.

    Returns:
        List of tuples (ir_file, iac_language, missing_lines, false_positives, file_name)
        for failed files.
        Empty list if all files pass.
    """
    print(f"Semantic check starting for type: {type_name}, CWE: {cwe_number} 🔍")

    tool.write_rule(type_name, rego_rule)

    folder = Path(examples_folder)
    if not examples:
        raise ValueError("No semantic examples provided")

    runner = CliRunner(mix_stderr=False)
    csv_path = Path.cwd() / f"{tool.name}_lint.csv"
    failures: List[Tuple[str, str, List[int], List[int], str]] = []

    for i, example in enumerate(examples, 1):
        print(f" Example #{i}/{len(examples)}:")
        script_path = folder / (example.get("file") or "")
        tech = tool.get_file_type(str(script_path)) if script_path else None
        if tech is None:
            print(
                f"  Skipping {script_path.name} (not supported by analysis tool '{tool.name}')"
            )
            continue
        if technologies is not None:
            if tech not in technologies:
                print(f"  Skipping {script_path.name} (technology {tech!r} not selected)")
                continue
        failure = _verify_examples(
            tool, runner, folder, example, type_name, csv_path
        )
        if failure is not None:
            failures.append(failure)
            if len(failures) >= 3:
                print(f"  Reached maximum of 3 failures, stopping verification")
                break

    if failures:
        print(f"Semantic check failed ❌ ({len(failures)} file(s) failed)")
        return failures
    print(f"Semantic check passed ✅")
    return []
