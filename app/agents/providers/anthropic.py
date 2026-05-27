"""Anthropic provider using native tool_use blocks and SSE streaming."""

import json
import time
import logging

import requests as http_requests

from .base import (
    LLMProvider, AgentEvent, EventType,
    ToolDef, ToolCall, ToolResult, LLMResponse,
)

log = logging.getLogger(__name__)

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):

    def _headers(self):
        return {
            "x-api-key": self.config.get("api_key", ""),
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def _model(self):
        return self.config.get("model") or "claude-sonnet-4-6-20250514"

    def format_tools(self, tools):
        result = []
        for t in tools:
            result.append({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })
        return result

    def format_tool_results(self, results):
        content = []
        for r in results:
            content.append({
                "type": "tool_result",
                "tool_use_id": r.tool_call_id,
                "content": r.content,
                "is_error": r.is_error,
            })
        return content

    def _prepare_messages(self, messages, tool_results=None):
        """Ensure messages alternate user/assistant, start with user,
        and preserve structured content blocks (tool_use / tool_result)."""
        prepared = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "system":
                role = "user"
                content = f"[Context Update]\n{content}"

            if role == "tool_results":
                prepared.append({"role": "user", "content": msg["content"]})
                continue

            # Reconstruct tool_use blocks for assistant messages stored with
            # tool_calls_raw (the non-streaming path stores them this way).
            if role == "assistant" and msg.get("tool_calls_raw"):
                blocks = []
                text_part = content if isinstance(content, str) else ""
                if text_part:
                    blocks.append({"type": "text", "text": text_part})
                for tc in msg["tool_calls_raw"]:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc.get("arguments", {}),
                    })
                content = blocks

            # Content is already a list of structured blocks (thinking, tool_use, tool_result, etc.)
            if isinstance(content, list):
                if prepared and prepared[-1]["role"] == role:
                    prev = prepared[-1]["content"]
                    if isinstance(prev, str):
                        prev = [{"type": "text", "text": prev}]
                    prepared[-1]["content"] = prev + content
                else:
                    prepared.append({"role": role, "content": content})
                continue

            # Plain string content — merge adjacent same-role messages
            if prepared and prepared[-1]["role"] == role:
                prev = prepared[-1]["content"]
                if isinstance(prev, str):
                    prepared[-1]["content"] = prev + "\n\n" + content
                elif isinstance(prev, list):
                    prepared[-1]["content"] = prev + [{"type": "text", "text": content}]
            else:
                prepared.append({"role": role, "content": content})

        if not prepared:
            prepared.append({"role": "user", "content": "Hello."})
        if prepared[0]["role"] != "user":
            prepared.insert(0, {"role": "user", "content": "Begin."})

        return prepared

    def _thinking_budget(self):
        return self.config.get("thinking_budget", 10000)

    def complete(self, messages, system_prompt="", tools=None, max_tokens=8000):
        budget = self._thinking_budget()
        if budget and budget > 0:
            max_tokens = max(max_tokens, budget + 4096)

        payload = {
            "model": self._model(),
            "max_tokens": max_tokens,
            "messages": self._prepare_messages(messages),
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = self.format_tools(tools)
        if budget and budget > 0:
            payload["thinking"] = {"type": "enabled", "budget_tokens": budget}
            payload.pop("temperature", None)

        for attempt in range(5):
            try:
                resp = http_requests.post(
                    API_URL, headers=self._headers(), json=payload, timeout=180,
                )
                if resp.status_code in (429, 529):
                    wait = max(int(resp.headers.get("retry-after", 0)), 2 ** attempt)
                    log.warning("Anthropic %d, retrying in %ds", resp.status_code, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except http_requests.exceptions.ConnectionError:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise
        else:
            raise RuntimeError("Anthropic API rate limit exceeded after retries")

        result = LLMResponse(
            stop_reason=data.get("stop_reason", ""),
            usage=data.get("usage", {}),
        )
        result.thinking_blocks = []
        for block in data.get("content", []):
            if block.get("type") == "thinking":
                result.thinking_blocks.append(block)
            elif block.get("type") == "text":
                result.text += block.get("text", "")
            elif block.get("type") == "tool_use":
                result.tool_calls.append(ToolCall(
                    id=block["id"],
                    name=block["name"],
                    arguments=block.get("input", {}),
                ))
        return result

    def stream(self, messages, system_prompt="", tools=None, max_tokens=8000):
        budget = self._thinking_budget()
        if budget and budget > 0:
            max_tokens = max(max_tokens, budget + 4096)

        payload = {
            "model": self._model(),
            "max_tokens": max_tokens,
            "stream": True,
            "messages": self._prepare_messages(messages),
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = self.format_tools(tools)
        if budget and budget > 0:
            payload["thinking"] = {"type": "enabled", "budget_tokens": budget}
            payload.pop("temperature", None)

        resp = None
        for attempt in range(5):
            try:
                resp = http_requests.post(
                    API_URL, headers=self._headers(), json=payload, timeout=300, stream=True,
                )
                if resp.status_code in (429, 529):
                    wait = max(int(resp.headers.get("retry-after", 0)), 2 ** attempt)
                    log.warning("Anthropic stream %d, retrying in %ds", resp.status_code, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                break
            except http_requests.exceptions.ConnectionError:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise
        else:
            raise RuntimeError("Anthropic stream API rate limit exceeded after retries")

        current_tool_id = None
        current_tool_name = None
        tool_input_json = ""
        in_thinking = False
        thinking_text_buf = ""
        thinking_signature = ""

        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            raw = line[6:]
            if raw == "[DONE]":
                break
            try:
                evt = json.loads(raw)
            except json.JSONDecodeError:
                continue

            evt_type = evt.get("type", "")

            if evt_type == "content_block_start":
                block = evt.get("content_block", {})
                if block.get("type") == "thinking":
                    in_thinking = True
                    thinking_text_buf = ""
                    thinking_signature = ""
                elif block.get("type") == "tool_use":
                    current_tool_id = block.get("id", "")
                    current_tool_name = block.get("name", "")
                    tool_input_json = ""
                    yield AgentEvent(EventType.TOOL_USE, {
                        "phase": "start",
                        "tool": current_tool_name,
                        "tool_call_id": current_tool_id,
                    })

            elif evt_type == "content_block_delta":
                delta = evt.get("delta", {})
                dtype = delta.get("type", "")
                if dtype == "thinking_delta":
                    chunk = delta.get("thinking", "")
                    thinking_text_buf += chunk
                    yield AgentEvent(EventType.THINKING, {"content": chunk})
                elif dtype == "signature_delta":
                    thinking_signature += delta.get("signature", "")
                elif dtype == "text_delta":
                    yield AgentEvent(EventType.TEXT_DELTA, {"content": delta.get("text", "")})
                elif dtype == "input_json_delta":
                    tool_input_json += delta.get("partial_json", "")

            elif evt_type == "content_block_stop":
                if in_thinking:
                    in_thinking = False
                    yield AgentEvent(EventType.THINKING, {
                        "type": "block_done",
                        "thinking": thinking_text_buf,
                        "signature": thinking_signature,
                    })
                elif current_tool_id:
                    try:
                        args = json.loads(tool_input_json) if tool_input_json else {}
                    except json.JSONDecodeError:
                        args = {}
                    yield AgentEvent(EventType.TOOL_USE, {
                        "phase": "complete",
                        "tool": current_tool_name,
                        "tool_call_id": current_tool_id,
                        "arguments": args,
                    })
                    current_tool_id = None
                    current_tool_name = None
                    tool_input_json = ""

            elif evt_type == "message_stop":
                yield AgentEvent(EventType.DONE, {})
