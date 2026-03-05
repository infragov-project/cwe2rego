import json
import re
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


def _normalize_example(raw: Dict[str, Any]) -> Dict[str, Any]:
    content = raw.get("content", "")
    if isinstance(content, str):
        content = content.replace("\\n", "\n")
    out = {
        "file": raw.get("file"),
        "content": content,
    }
    lines = raw.get("lines") or raw.get("line")
    if isinstance(lines, int):
        lines = [lines]
    out["lines"] = list(lines) if lines else []
    return out


def get_llm_examples(
    cwe_text: str,
    type_name: str,
    cwe_number: str,
    model_override: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    prompt_loader = get_prompt_loader()
    rendered = prompt_loader.load(
        "prompts/examplegeneration.md",
        cwe_text=cwe_text,
        type_name=type_name,
        cwe_number=cwe_number,
    )
    if model_override and api_key:
        provider = OpenRouterProvider(api_key=api_key)
        model = OpenRouterModel(model_override, provider=provider)
    else:
        model = examples_model_instance if examples_model_instance is not None else model_instance
    if model is None:
        raise ValueError("No model available for example generation; initialize_model or initialize_examples_model first")
    agent = InfraAgent(model=model, model_settings=model_settings)
    print(f"🤖 Generating examples for {type_name} (CWE-{cwe_number})...")
    result, _ = agent.run(rendered, message_history=[])
    raw = str(result) if result else ""
    raw = _strip_json_fences(raw)
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("LLM example output must be a JSON array")
    normalized = [_normalize_example(item) for item in data]
    for item in normalized:
        if not item.get("file") or not item.get("lines"):
            raise ValueError(f"Each example must have 'file' and 'lines'; got {item}")
    return normalized
