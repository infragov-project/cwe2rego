from pydantic_ai import Agent
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pydantic_ai.exceptions import UsageLimitExceeded, UnexpectedModelBehavior
from pydantic_ai.settings import ModelSettings
import asyncio
from typing import Callable, List, Any
from pydantic_ai.messages import ModelMessage


def _usage_get(obj: Any, key: str, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

class InfraAgent:
    def __init__(self, model, model_settings: ModelSettings | dict = {}, output_type: type = None):
        """Initialize the agent with optional custom instructions and output type."""
        self.model = model
        self.agent = Agent(
            model=self.model,
            model_settings=model_settings,
        )
        # self._output_type = output_type
    
    def add_tool(self, func: Callable) -> None:
        self.agent.tool_plain(func, sequential=True)


    @retry(
      retry=retry_if_exception_type((UsageLimitExceeded, UnexpectedModelBehavior)),
      stop=stop_after_attempt(3),
      wait=wait_exponential(multiplier=3, max=60),
    )
    async def run_stream_async(self, prompt: str, message_history: List[ModelMessage]=[]):
        """Run the agent asynchronously and return response with usage."""
        
        response = ""
        async with self.agent.run_stream(prompt, message_history=message_history) as result:
            async for message in result.stream_text(delta=True):
                print(message, end='', flush=True)
                response += message
        print()
        
        usage_data = result.usage() if hasattr(result, 'usage') else None
        
        prompt_tokens = _usage_get(usage_data, 'input_tokens', 0)
        completion_tokens = _usage_get(usage_data, 'output_tokens', 0)
        
        cache_read_tokens = _usage_get(usage_data, 'cache_read_tokens', 0) or 0
        usage_details = _usage_get(usage_data, 'details', {}) or {}
        if not isinstance(usage_details, dict):
            usage_details = {}

        reasoning_tokens = int(
            usage_details.get('reasoning_tokens')
            or 0
        )
        visible_completion_tokens = max(completion_tokens - reasoning_tokens, 0)

        print(
            f"Usage: prompt={prompt_tokens}, completion_total={completion_tokens}, "
            f"completion_visible={visible_completion_tokens}, reasoning={reasoning_tokens}, "
            f"cache_read_tokens={cache_read_tokens}"
        )
        
        return response, usage_data


    def run(self, prompt: str, message_history: List[ModelMessage]=[]):
        """Run the agent synchronously."""
        # Create event loop if needed
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.run_stream_async(prompt, message_history))
