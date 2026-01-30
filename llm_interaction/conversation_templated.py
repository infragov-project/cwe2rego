"""
Decorator for model interactions using prompt templates.
"""

from pydantic_ai.messages import ModelRequest, ModelResponse, UserPromptPart, TextPart
from pydantic_ai.models.openrouter import OpenRouterModel, OpenRouterModelSettings, OpenRouterProvider
from .agent import InfraAgent
from typing import Callable, TypeVar, get_type_hints
import inspect
from .prompt_loader import get_prompt_loader

T = TypeVar('T')

model_instance: OpenRouterModel = None
model_settings: OpenRouterModelSettings = None

def initialize_model(api_key: str, model: str):
    """Initialize the global model instance and settings."""
    provider=OpenRouterProvider(
        api_key=api_key
    )
    global model_instance
    model_instance = OpenRouterModel(model, provider=provider)

def initialize_model_settings():
    global model_settings
    model_settings = OpenRouterModelSettings(
        openrouter_reasoning={
            'effort': 'high',
        },
        openrouter_usage={
            'include': True,
        }
    )


def ask_model_prompt(template_path: str):
    """Decorator for model interactions using prompt templates.

    This decorator uses pydantic-ai to interact with the model.
    
    Args:
        template_path: Path to template file relative to model_prompts directory
        functions: Optional list of functions to make available to the model
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
            agent = InfraAgent(model=model_instance, model_settings=model_settings, output_type=return_type)
            
            # Add tools to the agent
            for tool_func in functions:
                agent.add_tool(tool_func)
            
            try:
                # Run the agent
                print(f"🤖 Model Prompt `{func.__name__}` (\"{template_path}\"):")
                result, usage = agent.run(rendered_prompt, message_history=chat_history if chat_history else [])
                    
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
