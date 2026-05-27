"""Abstract LLM provider interface and event types for the agent system."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generator


class EventType(Enum):
    TEXT_DELTA = "text_delta"
    THINKING = "thinking"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    AGENT_START = "agent_start"
    AGENT_DONE = "agent_done"
    VULNERABILITY = "vulnerability"
    ASK_USER = "ask_user"
    DONE = "done"
    ERROR = "error"


@dataclass
class AgentEvent:
    type: EventType
    data: dict = field(default_factory=dict)


@dataclass
class ToolDef:
    """Provider-agnostic tool definition."""
    name: str
    description: str
    parameters: dict  # JSON Schema for input parameters


@dataclass
class ToolCall:
    """A tool call requested by the model."""
    id: str
    name: str
    arguments: dict


@dataclass
class ToolResult:
    """Result of executing a tool call."""
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class LLMResponse:
    """Aggregated response from a non-streaming LLM call."""
    text: str = ""
    tool_calls: list = field(default_factory=list)
    stop_reason: str = ""
    usage: dict = field(default_factory=dict)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def complete(
        self,
        messages: list[dict],
        system_prompt: str = "",
        tools: list[ToolDef] | None = None,
        max_tokens: int = 8000,
    ) -> LLMResponse:
        """Synchronous completion. Returns full response."""
        ...

    @abstractmethod
    def stream(
        self,
        messages: list[dict],
        system_prompt: str = "",
        tools: list[ToolDef] | None = None,
        max_tokens: int = 8000,
    ) -> Generator[AgentEvent, None, None]:
        """Streaming completion. Yields AgentEvents."""
        ...

    @abstractmethod
    def format_tools(self, tools: list[ToolDef]) -> list[dict]:
        """Convert generic ToolDefs to provider-specific format."""
        ...

    @abstractmethod
    def format_tool_results(self, results: list[ToolResult]) -> list[dict]:
        """Format tool results for the next message to the provider."""
        ...
