from .base import LLMProvider, AgentEvent, EventType
from .anthropic import AnthropicProvider
from .openai_provider import OpenAIProvider
from .ollama import OllamaProvider

PROVIDER_MAP = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
}


def create_provider(name: str, config: dict) -> LLMProvider:
    cls = PROVIDER_MAP.get(name)
    if not cls:
        raise ValueError(f"Unknown provider: {name}. Available: {list(PROVIDER_MAP.keys())}")
    return cls(config)
