"""Ollama provider using the OpenAI-compatible API at localhost."""

import logging

from .openai_provider import OpenAIProvider

log = logging.getLogger(__name__)


class OllamaProvider(OpenAIProvider):
    """Wraps the OpenAI provider to target a local Ollama instance."""

    def _headers(self):
        return {"content-type": "application/json"}

    def _model(self):
        return self.config.get("model") or "llama3"

    def _api_url(self):
        base = self.config.get("base_url", "http://localhost:11434")
        return base.rstrip("/") + "/v1/chat/completions"
