"""OpenAI provider using function_calling and SSE streaming."""

import json
import time
import logging

import requests as http_requests

from .base import (
    LLMProvider, AgentEvent, EventType,
    ToolDef, ToolCall, ToolResult, LLMResponse,
)

log = logging.getLogger(__name__)

API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider(LLMProvider):

    def _headers(self):
        return {
            "authorization": f"Bearer {self.config.get('api_key', '')}",
            "content-type": "application/json",
        }

    def _model(self):
        return self.config.get("model") or "gpt-4o"

    def _api_url(self):
        return self.config.get("base_url", API_URL).rstrip("/") + "/chat/completions"

    def format_tools(self, tools):
        result = []
        for t in tools:
            result.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            })
        return result

    def format_tool_results(self, results):
        messages = []
        for r in results:
            messages.append({
                "role": "tool",
                "tool_call_id": r.tool_call_id,
                "content": r.content,
            })
        return messages

    def _build_messages(self, messages, system_prompt=""):
        oai_msgs = []
        if system_prompt:
            oai_msgs.append({"role": "system", "content": system_prompt})
        for msg in messages:
            role = msg.get("role", "user")
            if role == "system":
                role = "user"
            if role not in ("user", "assistant", "tool"):
                role = "user"

            content = msg.get("content", "")

            # Handle structured content blocks (Anthropic-format) that need
            # conversion to OpenAI format.
            if role == "assistant" and isinstance(content, list):
                text_parts = []
                tool_calls = []
                for block in content:
                    btype = block.get("type", "")
                    if btype == "thinking":
                        continue
                    elif btype == "text":
                        text_parts.append(block.get("text", ""))
                    elif btype == "tool_use":
                        tool_calls.append({
                            "id": block["id"],
                            "type": "function",
                            "function": {
                                "name": block["name"],
                                "arguments": json.dumps(block.get("input", {})),
                            },
                        })
                oai_msg = {"role": "assistant", "content": "\n".join(text_parts) or None}
                if tool_calls:
                    oai_msg["tool_calls"] = tool_calls
                oai_msgs.append(oai_msg)
                continue

            if role == "user" and isinstance(content, list):
                # tool_result blocks from Anthropic format — convert to
                # individual OpenAI tool messages
                for block in content:
                    if block.get("type") == "tool_result":
                        oai_msgs.append({
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id", ""),
                            "content": block.get("content", ""),
                        })
                    else:
                        oai_msgs.append({"role": "user", "content": str(block)})
                continue

            oai_msgs.append({"role": role, "content": content})
        return oai_msgs

    def complete(self, messages, system_prompt="", tools=None, max_tokens=8000):
        payload = {
            "model": self._model(),
            "messages": self._build_messages(messages, system_prompt),
            "temperature": 0.3,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = self.format_tools(tools)

        for attempt in range(5):
            try:
                resp = http_requests.post(
                    self._api_url(), headers=self._headers(), json=payload, timeout=180,
                )
                if resp.status_code == 429:
                    wait = max(int(resp.headers.get("retry-after", 0)), 2 ** attempt)
                    log.warning("OpenAI 429, retrying in %ds", wait)
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
            raise RuntimeError("OpenAI API rate limit exceeded after retries")

        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})

        result = LLMResponse(
            text=msg.get("content", "") or "",
            stop_reason=choice.get("finish_reason", ""),
            usage=data.get("usage", {}),
        )

        for tc in msg.get("tool_calls", []):
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = {}
            result.tool_calls.append(ToolCall(
                id=tc.get("id", ""),
                name=fn.get("name", ""),
                arguments=args,
            ))

        return result

    def stream(self, messages, system_prompt="", tools=None, max_tokens=8000):
        payload = {
            "model": self._model(),
            "messages": self._build_messages(messages, system_prompt),
            "temperature": 0.3,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if tools:
            payload["tools"] = self.format_tools(tools)

        resp = http_requests.post(
            self._api_url(), headers=self._headers(), json=payload, timeout=300, stream=True,
        )
        resp.raise_for_status()

        tool_calls_in_progress = {}

        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            raw = line[6:]
            if raw == "[DONE]":
                break
            try:
                chunk = json.loads(raw)
            except json.JSONDecodeError:
                continue

            choice = (chunk.get("choices") or [{}])[0]
            delta = choice.get("delta", {})

            if delta.get("content"):
                yield AgentEvent(EventType.TEXT_DELTA, {"content": delta["content"]})

            for tc_delta in delta.get("tool_calls", []):
                idx = tc_delta.get("index", 0)
                if idx not in tool_calls_in_progress:
                    tool_calls_in_progress[idx] = {
                        "id": tc_delta.get("id", ""),
                        "name": tc_delta.get("function", {}).get("name", ""),
                        "arguments": "",
                    }
                    yield AgentEvent(EventType.TOOL_USE, {
                        "phase": "start",
                        "tool": tool_calls_in_progress[idx]["name"],
                        "tool_call_id": tool_calls_in_progress[idx]["id"],
                    })

                arg_chunk = tc_delta.get("function", {}).get("arguments", "")
                if arg_chunk:
                    tool_calls_in_progress[idx]["arguments"] += arg_chunk

            if choice.get("finish_reason"):
                for idx, tc in tool_calls_in_progress.items():
                    try:
                        args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                    except json.JSONDecodeError:
                        args = {}
                    yield AgentEvent(EventType.TOOL_USE, {
                        "phase": "complete",
                        "tool": tc["name"],
                        "tool_call_id": tc["id"],
                        "arguments": args,
                    })
                tool_calls_in_progress = {}
                yield AgentEvent(EventType.DONE, {})
