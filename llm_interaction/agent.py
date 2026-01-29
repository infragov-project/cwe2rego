from pydantic_ai import Agent
from pydantic_ai import Agent, UnexpectedModelBehavior, capture_run_messages, PromptedOutput
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pydantic_ai.exceptions import UsageLimitExceeded, UnexpectedModelBehavior
from pydantic_ai.models.openrouter import OpenRouterModelSettings
import asyncio
from typing import Callable, List
from pydantic_ai.messages import ModelMessage

class InfraAgent:
    def __init__(self, model, model_settings: OpenRouterModelSettings={}, output_type: type = None):
        """Initialize the agent with optional custom instructions and output type."""
        self.model = model
        
        # Only pass output_type if it's not None
        if output_type is not None:
            # Endpoints that don't reliably support tool-based structured outputs (e.g., OpenRouter, AWS Bedrock)
            # Custom template with explicit instructions for clean JSON output
            # Note: curly braces must be doubled to escape them for str.format()
            json_template = (
                "Respond with valid JSON matching this schema:\n"
                "{schema}\n\n"
                "IMPORTANT: Output ONLY the JSON object, with no additional text or markdown formatting.\n\n"
                "Examples of correct JSON output:\n"
                '- For enums: {{"response": "rust"}} or {{"response": "python"}}\n'
                '- For lists: {{"response": ["item1", "item2"]}}\n'
                '- For multi-line strings, use \\n for newlines (not \\\\n): '
                '{{"code": "line1\\nline2\\nline3"}}'
            )
            self.agent = Agent(
                model=self.model,
                model_settings=model_settings,
                output_type=PromptedOutput(output_type, template=json_template),
            )
        else:
            self.agent = Agent(
                model=self.model,
                model_settings=model_settings,
            )
        self._output_type = output_type  # Store output type for later checks
    
    def add_tool(self, func: Callable) -> None:
        self.agent.tool_plain(func, sequential=True)

    @retry(
      retry=retry_if_exception_type((UsageLimitExceeded, UnexpectedModelBehavior)),
      stop=stop_after_attempt(3),
      wait=wait_exponential(multiplier=3, max=60),
    )
    async def run_async(self, prompt: str, message_history: List[ModelMessage]=[]):
        """Run the agent asynchronously and return response with usage."""
        
        # Reset usage limits on retry attempts (they are fresh for each agent.run()) # unnecessary for now
        with capture_run_messages() as messages:
            try:
                result = await self.agent.run(prompt, message_history=message_history)
            except (UsageLimitExceeded, UnexpectedModelBehavior) as e:
                raise
        
        # Convert pydantic-ai usage to our Usage dataclass
        usage_data = result.usage() if hasattr(result, 'usage') else None
        
        # Handle both text and structured output
        output = result.output
        
        return output, usage_data
    
    def run(self, prompt: str, message_history: List[ModelMessage]=[]):
        """Run the agent synchronously."""
        # Create event loop if needed
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.run_async(prompt, message_history))