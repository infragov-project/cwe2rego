"""
Decorator for model interactions using prompt templates.
"""

from pydantic_ai.messages import ModelRequest, ModelResponse, UserPromptPart, TextPart
from pydantic_ai.models import Model
from pydantic_ai.models.bedrock import BedrockConverseModel, BedrockModelSettings
from pydantic_ai.models.openrouter import OpenRouterModel, OpenRouterModelSettings, OpenRouterProvider
from pydantic_ai.settings import ModelSettings
from .agent import InfraAgent
from typing import Any, Callable, TypeVar, get_type_hints
import inspect
from .prompt_loader import get_prompt_loader

T = TypeVar('T')

model_instance: Model | None = None
examples_model_instance: Model | None = None
model_settings: ModelSettings | None = None
_usage_callback: Callable[[dict[str, Any]], None] | None = None


def set_usage_callback(callback: Callable[[dict[str, Any]], None] | None):
    """Register a callback that receives usage summary after each model call."""
    global _usage_callback
    _usage_callback = callback


def _usage_get(obj: Any, key: str, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _extract_usage_summary(usage: Any) -> dict[str, Any]:
    # Extract usage
    input_tokens = _usage_get(usage, "input_tokens", 0)
    output_tokens = _usage_get(usage, "output_tokens", 0)
    cache_read_tokens = _usage_get(usage, "cache_read_tokens", 0) or 0
    
    usage_details = _usage_get(usage, "details", {}) or {}
    if not isinstance(usage_details, dict):
        usage_details = {}
    
    reasoning_tokens = int(usage_details.get("reasoning_tokens") or 0)

    return {
        "input_tokens": int(input_tokens or 0),
        "output_tokens": int(output_tokens or 0),
        "reasoning_tokens": reasoning_tokens,
        "cache_read_tokens": cache_read_tokens,
    }

def _make_openrouter_model(api_key: str, model: str) -> OpenRouterModel:
    return OpenRouterModel(model, provider=OpenRouterProvider(api_key=api_key))

def _make_bedrock_model(model: str) -> BedrockConverseModel:
    return BedrockConverseModel(model)

def initialize_model(model: str, provider: str = 'openrouter', api_key: str | None = None):
    """Initialize the global model instance."""
    global model_instance
    if provider == 'bedrock':
        model_instance = _make_bedrock_model(model)
    else:
        model_instance = _make_openrouter_model(api_key, model)

def initialize_examples_model(model: str, provider: str = 'openrouter', api_key: str | None = None):
    """Initialize the model used for generating semantic-check examples."""
    global examples_model_instance
    if provider == 'bedrock':
        examples_model_instance = _make_bedrock_model(model)
    else:
        examples_model_instance = _make_openrouter_model(api_key, model)

def _bedrock_reasoning_fields(model: str) -> dict:
    if not model:
        return {}
    if model.startswith('zai.glm'):
        return {'reasoning_config': 'high'}
    if 'anthropic' in model:
        return {'thinking': {'type': 'enabled', 'budget_tokens': 16384}}
    if model.startswith('openai.'):
        return {'reasoning_effort': 'high'}
    return {}


def initialize_model_settings(model: str | None = None, provider: str = 'openrouter'):
    """Initialize model settings."""
    global model_settings
    if provider == 'bedrock':
        reasoning = _bedrock_reasoning_fields(model or '')
        settings = BedrockModelSettings(
            bedrock_cache_instructions=True,
            bedrock_cache_messages=True,
        )
        if reasoning:
            settings['bedrock_additional_model_requests_fields'] = reasoning
        model_settings = settings
    else:
        settings: OpenRouterModelSettings = {
            'openrouter_reasoning': {
                'effort': 'high',
            },
            'openrouter_usage': {
                'include': True,
            },
        }
        # Force Anthropic models to route through Amazon Bedrock on OpenRouter.
        if model and model.lower().startswith("anthropic/"):
            settings['openrouter_provider'] = {
                'order': ['amazon-bedrock'],
                'allow_fallbacks': False,
            }
        model_settings = OpenRouterModelSettings(**settings)

def ask_model_prompt(template_path: str):
    """Decorator for model interactions using prompt templates.

    This decorator uses pydantic-ai to interact with the model.
    
    Args:
        template_path: Path to template file relative to model_prompts directory
        TODO: functions: Optional list of functions to make available to the model
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:

            type_hints = get_type_hints(func)
            return_type = type_hints.get('return', type(None))

            # Get function signature to map args to param names
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Filter out None values and empty lists from arguments
            template_context = {
                k: v for k, v in bound_args.arguments.items() 
                if v is not None# and v != []
            }
            chat_history = template_context.pop('chat_history', None)

            # Load and render the template
            prompt_loader = get_prompt_loader()
            rendered_prompt = prompt_loader.load(template_path, **template_context)

            # Agent tools (functions)
            functions = []

            global model_instance
            global model_settings
            
            # Create agent with appropriate output type
            agent = InfraAgent(
                model=model_instance, 
                model_settings=model_settings, 
                output_type=return_type
            )
            
            # Add tools to the agent
            for tool_func in functions:
                agent.add_tool(tool_func)
            
            try:
                # Run the agent
                print(f"🤖 Model Prompt `{func.__name__}` (\"{template_path}\"):")
                result, usage = agent.run(rendered_prompt, message_history=chat_history if chat_history else [])
                
                if _usage_callback is not None:
                    _usage_callback(_extract_usage_summary(usage))

                if chat_history is not None:

                    user_message = ModelRequest(parts=[UserPromptPart(content=rendered_prompt)])

                    response_content = str(result) if result is not None else "(empty response)"
                    model_message = ModelResponse(parts=[TextPart(content=response_content)])

                    chat_history.append(user_message)
                    chat_history.append(model_message)

                return result

            except Exception as e:
                raise e
        
        return wrapper
    return decorator
