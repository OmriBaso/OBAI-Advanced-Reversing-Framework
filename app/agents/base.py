"""Base agent with agentic tool-use loop."""

import json
import uuid
import logging
from typing import Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from .providers.base import (
    LLMProvider, AgentEvent, EventType,
    ToolDef, ToolCall, ToolResult, LLMResponse,
)
from .tools import execute_tool

log = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 15
MAX_PARALLEL_TOOLS = 4
LOOP_GUARD_MAX_DUPES_PER_ROUND = 3


def _make_call_key(tc: ToolCall) -> str:
    """Create a hashable key for a tool call (name + sorted args)."""
    try:
        args_str = json.dumps(tc.arguments, sort_keys=True, default=str)
    except Exception:
        args_str = str(tc.arguments)
    return f"{tc.name}::{args_str}"


class BaseAgent:
    """Agent that runs an agentic loop: call LLM, execute tools, repeat."""

    name: str = "base"
    system_prompt: str = ""
    tools: list[ToolDef] = []

    def __init__(self, provider: LLMProvider, sess=None, db=None):
        self.provider = provider
        self.sess = sess
        self.db = db

    def build_system_prompt(self, context: dict) -> str:
        """Override to build a dynamic system prompt from context."""
        return self.system_prompt

    def _build_assistant_msg(self, text, tool_calls, thinking_blocks=None):
        """Build an assistant message with proper content blocks (thinking + text + tool_use).
        thinking_blocks should be a list of {"thinking": ..., "signature": ...} dicts."""
        content = []
        for tb in (thinking_blocks or []):
            block = {"type": "thinking", "thinking": tb["thinking"]}
            if tb.get("signature"):
                block["signature"] = tb["signature"]
            content.append(block)
        if text:
            content.append({"type": "text", "text": text})
        for tc in tool_calls:
            content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            })
        return {"role": "assistant", "content": content if content else text}

    def _append_tool_results(self, conversation, tool_results):
        """Append tool results to conversation in the right format."""
        formatted = self.provider.format_tool_results(tool_results)
        if isinstance(formatted, list) and formatted and isinstance(formatted[0], dict):
            if formatted[0].get("role") == "tool":
                conversation.extend(formatted)
            else:
                conversation.append({"role": "user", "content": formatted})
        else:
            conversation.append({"role": "user", "content": formatted})

    def _execute_tools_parallel(self, tool_calls):
        """Execute tool calls in parallel using a thread pool. Returns results in original order."""
        if len(tool_calls) <= 1:
            results = []
            for tc in tool_calls:
                r = execute_tool(tc, self.sess, self.db)
                r.tool_call_name = tc.name
                results.append(r)
            return results

        results_by_id = {}
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_TOOLS) as pool:
            future_to_tc = {pool.submit(execute_tool, tc, self.sess, self.db): tc for tc in tool_calls}
            for future in as_completed(future_to_tc):
                tc = future_to_tc[future]
                try:
                    result = future.result()
                except Exception as e:
                    log.exception("Parallel tool execution error for %s", tc.name)
                    result = ToolResult(tc.id, f"Tool error: {e}", is_error=True)
                result.tool_call_name = tc.name
                results_by_id[tc.id] = result

        return [results_by_id[tc.id] for tc in tool_calls]

    def run(self, messages: list[dict], context: dict | None = None) -> LLMResponse:
        """Run the agentic loop synchronously. Returns the final text response."""
        context = context or {}
        system_prompt = self.build_system_prompt(context)
        conversation = list(messages)
        collected_text = ""
        all_vulns = []
        all_exploits = []
        seen_calls: set[str] = set()

        for round_num in range(MAX_TOOL_ROUNDS):
            response = self.provider.complete(
                conversation,
                system_prompt=system_prompt,
                tools=self.tools if self.tools else None,
            )

            if response.text:
                collected_text += response.text

            if not response.tool_calls:
                break

            conversation.append(self._build_assistant_msg(response.text, response.tool_calls))

            dupes_this_round = 0
            tool_results = []
            for tc in response.tool_calls:
                if tc.name == "report_vulnerability":
                    all_vulns.append(tc.arguments)
                elif tc.name == "submit_exploit":
                    all_exploits.append(tc.arguments)

                call_key = _make_call_key(tc)
                if call_key in seen_calls:
                    dupes_this_round += 1
                    result = ToolResult(tc.id, "Duplicate call — use different arguments or pagination.", is_error=True)
                    result.tool_call_name = tc.name
                    tool_results.append(result)
                else:
                    seen_calls.add(call_key)
                    result = execute_tool(tc, self.sess, self.db)
                    result.tool_call_name = tc.name
                    tool_results.append(result)

            self._append_tool_results(conversation, tool_results)

            if dupes_this_round >= LOOP_GUARD_MAX_DUPES_PER_ROUND:
                collected_text += "\n\n[Loop guard triggered — returning partial findings.]\n\n"
                break

        result = LLMResponse(text=collected_text, stop_reason="end_turn")
        result.tool_calls = []
        result.usage = {"vulnerabilities": all_vulns, "exploits": all_exploits}
        return result

    def run_streaming(self, messages: list[dict], context: dict | None = None) -> Generator[AgentEvent, None, None]:
        """Run the agentic loop with streaming. Yields AgentEvents."""
        context = context or {}
        system_prompt = self.build_system_prompt(context)
        conversation = list(messages)
        seen_calls: set[str] = set()

        for round_num in range(MAX_TOOL_ROUNDS):
            collected_text = ""
            thinking_blocks = []
            pending_tool_calls = []

            for event in self.provider.stream(
                conversation,
                system_prompt=system_prompt,
                tools=self.tools if self.tools else None,
            ):
                if event.type == EventType.THINKING:
                    if event.data.get("type") == "block_done":
                        thinking_blocks.append({
                            "thinking": event.data.get("thinking", ""),
                            "signature": event.data.get("signature", ""),
                        })
                    else:
                        yield event

                elif event.type == EventType.TEXT_DELTA:
                    collected_text += event.data.get("content", "")
                    yield event

                elif event.type == EventType.TOOL_USE:
                    if event.data.get("phase") == "start":
                        yield AgentEvent(EventType.TOOL_USE, {
                            "tool": event.data.get("tool", ""),
                            "phase": "start",
                        })
                    elif event.data.get("phase") == "complete":
                        tc = ToolCall(
                            id=event.data.get("tool_call_id", str(uuid.uuid4())),
                            name=event.data.get("tool", ""),
                            arguments=event.data.get("arguments", {}),
                        )
                        pending_tool_calls.append(tc)

                elif event.type == EventType.DONE:
                    pass

            if not pending_tool_calls:
                yield AgentEvent(EventType.DONE, {})
                return

            conversation.append(self._build_assistant_msg(collected_text, pending_tool_calls, thinking_blocks))

            dupes_this_round = 0
            tool_results = []

            for tc in pending_tool_calls:
                if tc.name == "report_vulnerability":
                    yield AgentEvent(EventType.VULNERABILITY, tc.arguments)

                call_key = _make_call_key(tc)
                if call_key in seen_calls:
                    dupes_this_round += 1
                    log.warning("Loop guard: duplicate call %s(%s) in round %d",
                                tc.name, tc.arguments, round_num)
                    result = ToolResult(
                        tc.id,
                        "You already called this tool with identical arguments in a previous round. "
                        "The result was the same. Use pagination parameters (start_line, offset) to get "
                        "different data, try different arguments, or summarize what you have and respond "
                        "to the user.",
                        is_error=True,
                    )
                    result.tool_call_name = tc.name
                    tool_results.append(result)
                else:
                    seen_calls.add(call_key)
                    yield AgentEvent(EventType.TOOL_USE, {
                        "tool": tc.name,
                        "phase": "executing",
                        "arguments": tc.arguments,
                    })
                    result = execute_tool(tc, self.sess, self.db)
                    result.tool_call_name = tc.name
                    tool_results.append(result)

            if dupes_this_round >= LOOP_GUARD_MAX_DUPES_PER_ROUND:
                log.warning("Loop guard: %d duplicate calls in round %d — forcing stop",
                            dupes_this_round, round_num)
                yield AgentEvent(EventType.TEXT_DELTA, {
                    "content": "\n\n[I've detected I'm repeating the same tool calls. "
                               "Here is what I found so far based on the data I've gathered:]\n\n",
                })
                self._append_tool_results(conversation, tool_results)
                yield AgentEvent(EventType.DONE, {})
                return

            for result in tool_results:
                yield AgentEvent(EventType.TOOL_RESULT, {
                    "tool": result.tool_call_name if hasattr(result, 'tool_call_name') else "",
                    "summary": result.content[:200],
                    "is_error": result.is_error,
                })

            self._append_tool_results(conversation, tool_results)

        yield AgentEvent(EventType.DONE, {})
