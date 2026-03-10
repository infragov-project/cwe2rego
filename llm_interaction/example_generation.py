import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic_ai.models.openrouter import OpenRouterModel, OpenRouterProvider

from .agent import InfraAgent
from .conversation_templated import (
    examples_model_instance,
    model_instance,
    model_settings,
)
from .prompt_loader import get_prompt_loader


def _strip_json_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```+\s*json?\s*\n?", "", text)
    text = re.sub(r"\n?```+\s*$", "", text)
    return text.strip()


def _normalize_lines(lines: Any) -> List[int]:
    if lines is None:
        return []

    if isinstance(lines, int):
        candidates: List[Any] = [lines]
    elif isinstance(lines, list):
        candidates = lines
    else:
        candidates = [lines]

    normalized: List[int] = []
    seen: set[int] = set()
    for item in candidates:
        if isinstance(item, int):
            line_number = item
        elif isinstance(item, str) and item.strip().isdigit():
            line_number = int(item.strip())
        else:
            continue

        if line_number <= 0 or line_number in seen:
            continue

        seen.add(line_number)
        normalized.append(line_number)

    return normalized


def _normalize_generated_example(raw: Dict[str, Any]) -> Dict[str, Any]:
    content = raw.get("content", "")
    if isinstance(content, str):
        content = content.replace("\\n", "\n")

    return {
        "file": raw.get("file"),
        "content": content,
    }


def _normalize_annotation(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file": raw.get("file"),
        "lines": _normalize_lines(raw.get("lines") or raw.get("line")),
    }


def _load_examples_manifest(folder: Path, cwe_number: str) -> List[Dict[str, Any]]:
    manifest_path = folder / f"cwe-{cwe_number}.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"JSON manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as file_handle:
        data = json.load(file_handle)

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "examples" in data:
        return data["examples"]
    raise ValueError("Unsupported manifest format; expected list or dict with 'examples'")


def _load_examples_with_content(folder: Path, cwe_number: str) -> List[Dict[str, Any]]:
    examples = _load_examples_manifest(folder, cwe_number)
    hydrated_examples: List[Dict[str, Any]] = []

    for example in examples:
        file_name = example.get("file")
        if not file_name:
            raise ValueError(f"Example entry missing 'file': {example}")

        file_path = folder / file_name
        if not file_path.exists():
            raise FileNotFoundError(f"Example file not found: {file_path}")

        hydrated_example = dict(example)
        hydrated_example["content"] = file_path.read_text(encoding="utf-8")
        hydrated_examples.append(hydrated_example)

    return hydrated_examples


def _normalize_cwe_number(cwe_number: str) -> str:
    match = re.search(r"(\d+)", str(cwe_number))
    if match is None:
        raise ValueError(f"Invalid CWE number: {cwe_number}")
    return match.group(1)


def _get_annotation_reference_cwe(cwe_number: str) -> str:
    normalized_cwe = _normalize_cwe_number(cwe_number)
    return "284" if normalized_cwe == "353" else "353"


def _load_annotation_reference_examples(cwe_number: str) -> tuple[str, List[Dict[str, Any]]]:
    reference_cwe = _get_annotation_reference_cwe(cwe_number)
    examples_folder = (
        Path(__file__).resolve().parent.parent
        / "validation"
        / "examples"
        / f"CWE-{reference_cwe}"
    )
    examples = _load_examples_with_content(examples_folder, reference_cwe)

    reference_examples: List[Dict[str, Any]] = []
    for item in examples:
        reference_examples.append(
            {
                "file": item["file"],
                "numbered_content": add_line_numbers(item["content"]),
                "annotated_lines": _normalize_lines(item.get("lines") or item.get("line")),
            }
        )

    return reference_cwe, reference_examples


def _resolve_examples_model(model_override: Optional[str], api_key: Optional[str]):
    if model_override and api_key:
        provider = OpenRouterProvider(api_key=api_key)
        return OpenRouterModel(model_override, provider=provider)

    model = examples_model_instance if examples_model_instance is not None else model_instance
    if model is None:
        raise ValueError(
            "No model available for example generation; initialize_model or initialize_examples_model first"
        )
    return model


def _run_llm_prompt(
    agent: InfraAgent,
    prompt_template: str,
    **template_vars,
) -> List[Dict[str, Any]]:
    """Run an LLM prompt and return parsed JSON array response."""
    prompt_loader = get_prompt_loader()
    rendered = prompt_loader.load(prompt_template, **template_vars)
    
    result, _ = agent.run(rendered, message_history=[])
    raw = str(result) if result else ""
    raw = _strip_json_fences(raw)
    data = json.loads(raw)
    
    if not isinstance(data, list):
        raise ValueError(f"LLM output must be a JSON array, got {type(data).__name__}")
    
    return data


def add_line_numbers(content: str) -> str:
    """Prefix each line with 1-based line numbers for annotation prompts."""
    lines = content.splitlines()
    if not lines:
        return ""
    return "\n".join(f"{index}: {line}" for index, line in enumerate(lines, start=1))


def _build_numbered_files_for_annotation(examples: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    numbered_files: List[Dict[str, str]] = []
    for item in examples:
        file_name = item.get("file")
        content = item.get("content")
        if not file_name:
            raise ValueError(f"Each example must have 'file'; got {item}")
        if not isinstance(content, str):
            raise ValueError(f"Each example must have string 'content'; got {item}")

        numbered_files.append(
            {
                "file": file_name,
                "numbered_content": add_line_numbers(content),
            }
        )

    return numbered_files


def _merge_examples_with_annotations(
    examples: List[Dict[str, Any]],
    annotations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    annotation_by_file: Dict[str, List[int]] = {
        item["file"]: item["lines"]
        for item in annotations
    }

    merged: List[Dict[str, Any]] = []
    missing_files: List[str] = []
    empty_line_files: List[str] = []

    for item in examples:
        file_name = item.get("file")
        if not file_name:
            raise ValueError(f"Each example must have 'file'; got {item}")

        if file_name not in annotation_by_file:
            missing_files.append(file_name)
            continue

        lines = annotation_by_file[file_name]
        if not lines:
            empty_line_files.append(file_name)

        merged.append(
            {
                "file": file_name,
                "content": item.get("content", ""),
                "lines": lines,
            }
        )

    if missing_files:
        raise ValueError(f"Missing annotation entries for file(s): {', '.join(sorted(missing_files))}")
    if empty_line_files:
        raise ValueError(f"Missing annotated lines for file(s): {', '.join(sorted(empty_line_files))}")

    return merged


def get_llm_examples(
    cwe_text: str,
    type_name: str,
    cwe_number: str,
    model_override: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    model = _resolve_examples_model(model_override, api_key)
    agent = InfraAgent(model=model, model_settings=model_settings)
    
    print(f"🤖 Generating examples for {type_name} (CWE-{cwe_number})...")
    data = _run_llm_prompt(
        agent,
        "prompts/examplegeneration.md",
        cwe_text=cwe_text,
        type_name=type_name,
        cwe_number=cwe_number,
    )

    normalized = [_normalize_generated_example(item) for item in data]
    seen_files: set[str] = set()
    for item in normalized:
        file_name = item.get("file")
        if not file_name:
            raise ValueError(f"Each example must have 'file'; got {item}")
        if file_name in seen_files:
            raise ValueError(f"Duplicate generated file name '{file_name}'")
        seen_files.add(file_name)
        if not isinstance(item.get("content"), str) or not item.get("content"):
            raise ValueError(f"Each example must have non-empty 'content'; got {item}")

    numbered_files = _build_numbered_files_for_annotation(normalized)
    annotations = get_llm_example_annotations(
        agent=agent,
        cwe_text=cwe_text,
        type_name=type_name,
        cwe_number=cwe_number,
        numbered_files=numbered_files,
    )

    return _merge_examples_with_annotations(normalized, annotations)


def get_llm_example_annotations(
    agent: InfraAgent,
    cwe_text: str,
    type_name: str,
    cwe_number: str,
    numbered_files: List[Dict[str, str]],
) -> List[Dict[str, Any]]:
    if not numbered_files:
        raise ValueError("numbered_files must not be empty")

    reference_cwe, reference_examples = _load_annotation_reference_examples(cwe_number)

    print(f"🤖 Annotating smelly lines for {type_name} (CWE-{cwe_number})...")
    data = _run_llm_prompt(
        agent,
        "prompts/exampleannotation.md",
        cwe_text=cwe_text,
        type_name=type_name,
        cwe_number=cwe_number,
        reference_cwe_number=reference_cwe,
        reference_examples=reference_examples,
        files=numbered_files,
    )

    annotations = [_normalize_annotation(item) for item in data]
    expected_files = {item["file"] for item in numbered_files}
    seen_files: set[str] = set()
    for item in annotations:
        file_name = item.get("file")
        if not file_name:
            raise ValueError(f"Each annotation must include 'file'; got {item}")
        if file_name not in expected_files:
            raise ValueError(f"Annotation returned unknown file '{file_name}'")
        if file_name in seen_files:
            raise ValueError(f"Duplicate annotation entry for file '{file_name}'")
        seen_files.add(file_name)

    missing_files = sorted(expected_files - seen_files)
    if missing_files:
        raise ValueError(f"Missing annotation entries for file(s): {', '.join(missing_files)}")

    return annotations
