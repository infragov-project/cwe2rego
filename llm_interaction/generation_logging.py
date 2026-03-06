"""Utilities for experiment-aware generation logging."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_INVALID_TOKEN_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_DUPLICATE_SEPARATORS = re.compile(r"[_-]{2,}")


def _normalize_file_token(value: str) -> str:
    """Normalize free-form text into a filename-safe token."""
    token = value.strip().lower()
    token = re.sub(r"\s+", "_", token)
    token = _INVALID_TOKEN_CHARS.sub("_", token)
    token = _DUPLICATE_SEPARATORS.sub("_", token)
    token = token.strip("._-")
    if token in {".", ".."}:
        return ""
    return token


def sanitize_file_token(value: str | None, fallback: str = "default") -> str:
    """Return a safe token for filenames and directory names."""
    raw_value = value if value is not None else ""
    token = _normalize_file_token(raw_value)
    if token:
        return token

    fallback_token = _normalize_file_token(fallback)
    if fallback_token:
        return fallback_token

    raise ValueError("Unable to build a safe filename token from input")


def model_to_directory_name(model: str) -> str:
    """Convert a model identifier to a filesystem-safe directory name."""
    model_tail = model.split("/")[-1] if model else ""
    return sanitize_file_token(model_tail, fallback="model")


def build_run_paths(
    base_dir: Path,
    model: str,
    cwe: str,
    experiment_name: str | None,
) -> dict[str, Any]:
    """Build output paths for a generation run.

    The experiment token is required and is used for directory grouping.
    """
    model_name = model_to_directory_name(model)
    experiment_token = sanitize_file_token(experiment_name, fallback="")
    run_timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    model_directory = base_dir / "generated_rego" / experiment_token / model_name
    output_path = model_directory / f"cwe_{cwe}.rego"
    log_path = model_directory / "logs" / f"cwe_{cwe}__model_{model_name}__{run_timestamp}.json"
    generated_examples_dir = model_directory / "generated_examples" / f"CWE-{cwe}"

    return {
        "model_name": model_name,
        "experiment_name": experiment_token,
        "model_directory": model_directory,
        "output_path": output_path,
        "log_path": log_path,
        "generated_examples_dir": generated_examples_dir,
    }


def create_generation_log(
    *,
    cwe: str,
    type_name: str,
    model_used: str,
    use_rag: bool,
    output_rego_path: Path,
    cwe_condition: str,
    use_llm_examples: bool,
    examples_model: str | None,
    generated_examples_dir: Path,
    experiment_name: str,
) -> dict[str, Any]:
    """Create the initial generation log payload."""
    return {
        "run_started_at_utc": datetime.now(timezone.utc).isoformat(),
        "experiment_name": experiment_name,
        "cwe": cwe,
        "type_name": type_name,
        "model_used": model_used,
        "use_rag": use_rag,
        "output_rego_path": str(output_rego_path.resolve()),
        "cwe_condition": cwe_condition,
        "example_generation": {
            "enabled": use_llm_examples,
            "model": examples_model if use_llm_examples else None,
            "directory": str(generated_examples_dir.resolve()) if use_llm_examples else None,
            "files": [],
        },
        "iterations": [],
        "result": {
            "passed": False,
            "attempts_used": 0,
            "max_attempts": 0,
            "ended_at_utc": None,
        },
    }


def persist_generation_log(log_path: Path, payload: dict[str, Any]) -> None:
    """Persist the current generation log payload as formatted JSON."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def list_generated_example_files(examples_dir: Path) -> list[str]:
    """Return all generated example file paths for logging."""
    if not examples_dir.exists():
        return []
    return sorted(str(path.resolve()) for path in examples_dir.rglob("*") if path.is_file())


def serialize_semantic_failures(failures: list[tuple]) -> list[dict[str, Any]]:
    """Convert semantic failure tuples into JSON-serializable error entries."""
    serialized: list[dict[str, Any]] = []
    for ir_file, iac_language, missing_lines, false_positives in failures:
        serialized.append(
            {
                "error_type": "semantic",
                "annotation": "Semantic validation mismatch between expected and detected lines",
                "iac_language": iac_language,
                "missing_lines": missing_lines,
                "false_positives": false_positives,
                "ir_file": ir_file,
            }
        )
    return serialized


def update_result_progress(payload: dict[str, Any], max_attempts: int) -> None:
    """Update attempt counters in the log payload."""
    payload["result"]["attempts_used"] = len(payload["iterations"])
    payload["result"]["max_attempts"] = max_attempts


def append_iteration(payload: dict[str, Any], iteration_log: dict[str, Any], max_attempts: int) -> None:
    """Append an iteration entry and refresh counters."""
    payload["iterations"].append(iteration_log)
    update_result_progress(payload, max_attempts)


def finalize_generation_log(payload: dict[str, Any], passed: bool, max_attempts: int) -> None:
    """Finalize result metadata at the end of a generation run."""
    payload["result"]["passed"] = passed
    update_result_progress(payload, max_attempts)
    
    end_time = datetime.now(timezone.utc)
    payload["result"]["ended_at_utc"] = end_time.isoformat()
    
    # Calculate elapsed time
    start_time = datetime.fromisoformat(payload["run_started_at_utc"])
    elapsed_seconds = int((end_time - start_time).total_seconds())
    minutes = elapsed_seconds // 60
    seconds = elapsed_seconds % 60
    payload["result"]["elapsed_time"] = f"{minutes}m{seconds}s"
