"""Utilities for managing conversation history during iterative generation."""

from collections.abc import MutableSequence
from typing import Any

from pydantic_ai.messages import ModelResponse, TextPart


def trim_validation_history(
    history: MutableSequence[Any],
    max_iterations: int,
    pinned_messages: int = 1,
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

    max_tail_messages = max_iterations
    tail_length = len(history) - pinned_messages
    if tail_length <= max_tail_messages:
        return

    trim_start = pinned_messages
    trim_end = len(history) - max_tail_messages
    del history[trim_start:trim_end]


def append_iteration_summary_to_history(
    conversation_history: list,
    summary: str,
) -> None:
    """Append a natural language iteration summary to conversation history."""
    conversation_history.append(
        ModelResponse(parts=[TextPart(content=summary)])
    )