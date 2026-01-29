"""
Interact with LLM via Pydantic framework (main file).
"""

from pydantic_ai.providers.openrouter import OpenRouterProvider
from pydantic_ai.models.openrouter import OpenRouterModel, OpenRouterModelSettings
from .conversation_templated import ask_model_prompt
from .conversation_templated import initialize_model, initialize_model_settings
import os
from argparse import ArgumentParser


@ask_model_prompt("prompts/weather.md")
def get_weather_report(location: str, chat_history=None) -> str:
    """Get a weather report for a given location."""
    ...


if __name__ == "__main__":
    parser = ArgumentParser(description="LLM Interaction Client")
    parser.add_argument("model", help="Model to use (e.g., openai/gpt-5-mini)")
    args = parser.parse_args()

    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")
    
    initialize_model_settings()
    if not args.model:
        raise ValueError("Model argument is required")
    initialize_model(OPENROUTER_API_KEY, "openai/gpt-5-mini")

    conversation_history = []
    print(get_weather_report(location="San Francisco, CA"))
    print(get_weather_report(location="New York, NY", chat_history=conversation_history))
    