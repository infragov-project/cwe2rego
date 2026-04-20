"""Utilities for managing conversation history during iterative generation."""

import json
from collections.abc import MutableSequence
from typing import Any


def trim_validation_history(
    history: MutableSequence[Any],
    max_iterations: int,
    pinned_messages: int = 2,
) -> None:
    """Keep the first pinned messages and only the last N validation-fix iterations.

    Each iteration corresponds to 2 chat messages (user prompt + model response).
    If ``max_iterations == 0``, only the pinned messages are kept.
    If ``max_iterations < 0``, the full validation history is preserved.
    """
    if pinned_messages < 0:
        raise ValueError("pinned_messages must be >= 0")

    if max_iterations < 0:
        return

    if len(history) <= pinned_messages:
        return

    if max_iterations == 0:
        del history[pinned_messages:]
        return

    max_tail_messages = max_iterations * 2
    tail_length = len(history) - pinned_messages
    if tail_length <= max_tail_messages:
        return

    trim_start = pinned_messages
    trim_end = len(history) - max_tail_messages
    del history[trim_start:trim_end]


def build_syntactic_error_summary(rego_rule: str, error_message: str) -> dict:
    """Build a compact JSON summary for a syntactic validation failure.
    
    Args:
        rego_rule: The Rego rule that failed
        error_message: The error message from OPA validation
    
    Returns:
        Compact summary dict
    """
    return {
        "rego_rule": rego_rule,
        "problem": "syntactic",
        "error": error_message
    }


def build_semantic_error_summary(
    rego_rule: str,
    failures: list,
    passed: list,
) -> dict:
    """Build a compact JSON summary for a semantic validation failure.
    
    Args:
        rego_rule: The Rego rule that was tested
        failures: List of failed tuples (ir_file, iac_language, missing_lines, false_positives, file_name)
        passed: List of passed tuples (file_name, technology)
    
    Returns:
        Compact summary dict with all files (passed and failed)
    """
    files = []
    
    # Add failed files with details
    for f in failures:
        ir_file = f[0]
        iac_language = f[1]
        missing_lines = f[2]
        false_positives = f[3]
        file_name = f[4]
        
        file_obj = {
            "file": file_name,
            "status": "failed",
        }
        if missing_lines:
            file_obj["false_negatives"] = missing_lines
        if false_positives:
            file_obj["false_positives"] = false_positives
        files.append(file_obj)
    
    # Add passed files
    for file_name, tech in passed:
        files.append({
            "file": file_name,
            "status": "passed",
            "technology": tech
        })
    
    return {
        "rego_rule": rego_rule,
        "problem": "semantic",
        "files": files
    }


def append_iteration_summary_to_history(
    conversation_history: list,
    summary: dict,
) -> None:
    """Append a compact iteration summary to conversation history.
    
    Args:
        conversation_history: List of message dicts to append to
        summary: Summary dict (from build_syntactic_error_summary or build_semantic_error_summary)
    """
    conversation_history.append({
        "role": "assistant",
        "content": json.dumps(summary, indent=2)
    })