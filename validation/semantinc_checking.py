import csv
import json
import sys
from typing import Tuple, List, Dict, Any
from enum import Enum
from pathlib import Path
from click.testing import CliRunner

# Add GLITCH directory to path so glitch module can be imported
sys.path.insert(0, str(Path(__file__).parent / "GLITCH"))

from glitch.__main__ import repr as glitch_repr, lint as glitch_lint

class FileType(Enum):
    ANSIBLE = "ansible"
    CHEF = "chef"
    PUPPET = "puppet"

EXTENSION_MAP = {
    ".yml": FileType.ANSIBLE,
    ".yaml": FileType.ANSIBLE,
    ".rb": FileType.CHEF,
    ".pp": FileType.PUPPET,
}

def get_file_type(file_path: str) -> FileType | None:
    ext = Path(file_path).suffix.lower()
    return EXTENSION_MAP.get(ext)

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


def _verify_examples(
    runner: CliRunner,
    folder: Path,
    example: Dict[str, Any],
    type_name: str,
    csv_path: Path,
) -> Tuple[str, str, List[int]] | None:
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

    file_type = get_file_type(str(script_path))
    if file_type is None:
        raise ValueError(f"Unsupported file type: {script_path}")

    unit_type = example.get("type") or "unknown"

    # Remove any previous CSV to avoid stale results.
    if csv_path.exists():
        csv_path.unlink()

    result = runner.invoke(
        glitch_lint,
        [
            "--tech",
            file_type.value,
            "--type",
            unit_type,
            "--csv",
            "--smell-types",
            "security",
            str(script_path),
            str(csv_path),
        ],
    )
    if result.exception:
        raise result.exception

    if not csv_path.exists():
        raise FileNotFoundError(f"GLITCH did not produce CSV: {csv_path}")

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
    missing = [line for line in expected_lines if line not in detected_set]
    if missing:
        ir = extract_ir(str(script_path), unit_type)
        return (ir, file_type.value, missing)

    return None


def semantic_check(rego_rule: str, type_name: str, cwe_number: str) -> Tuple[str, str, List[int]] | None:
    """
    Load the JSON examples manifest for a CWE folder.
    
    Args:
        rego_rule: The generated Rego rule content
        type_name: The smell code name (e.g., 'sec_hardcoded_secret')
        cwe_number: CWE number (e.g., "1327")
        
    Returns:
        Tuple of (ir_file, iac_language, line_number) if validation fails, None if passes
    """
    # Write rule to GLITCH security directory using type_name
    glitch_dir = Path(__file__).parent / "GLITCH"
    rule_path = glitch_dir / "glitch" / "rego" / "queries" / "security" / f"{type_name}.rego"
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    with open(rule_path, "w") as f:
        f.write(rego_rule)

    folder = Path(__file__).parent / "examples" / f"CWE-{cwe_number}"
    examples = _load_examples(folder, cwe_number)

    runner = CliRunner()
    csv_path = Path.cwd() / "glitch_lint.csv"

    for example in examples:
        failure = _verify_examples(runner, folder, example, type_name, csv_path)
        if failure is not None:
            return failure

    return None

def extract_ir(file_path: str, file_type_glitch: str) -> str:
    """
    Extract the Intermediate Representation (IR) from the given file path using GLITCH's repr command via CliRunner.
    
    Args:
        file_path: Path to the file to extract IR from
        file_type_glitch: The file type as expected by GLITCH (e.g., "script", "task", "vars")
    Returns:
        JSON string representation of the IR
        
    Raises:
        ValueError: If the file type is not supported
        Exception: If GLITCH repr command fails
    """
    # Get the file type
    file_type = get_file_type(file_path)
    if file_type is None:
        raise ValueError(f"Unsupported file type: {Path(file_path).suffix}")
    
    # Use CliRunner to invoke GLITCH repr command
    runner = CliRunner()
    result = runner.invoke(
        glitch_repr,
        [
            "--tech",
            file_type.value,
            "--type",
            file_type_glitch,
            file_path,
        ],
    )
    
    if result.exception:
        raise result.exception
    
    if result.exit_code != 0:
        raise Exception(f"GLITCH repr command failed with exit code {result.exit_code}\nOutput: {result.output}")
    
    # Return the IR output directly
    return result.output