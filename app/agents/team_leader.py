"""Team Leader base class — manages a team briefing, can do work or delegate to workers."""

import uuid
import logging
from typing import Generator

from .base import BaseAgent, _make_call_key, LOOP_GUARD_MAX_DUPES_PER_ROUND
from .providers.base import (
    LLMProvider, AgentEvent, EventType,
    ToolDef, ToolCall, ToolResult,
)
from .tools import execute_tool
from ..config import now_iso
from ..models.database import read_db, write_db

log = logging.getLogger(__name__)

MAX_LEADER_ROUNDS = 15


class WorkerAgent(BaseAgent):
    """Lightweight stateless worker spawned by a team leader for heavy tasks."""

    def __init__(self, provider, sess, db, worker_name, tools, system_prompt_text):
        super().__init__(provider, sess, db)
        self.name = worker_name
        self.tools = tools
        self._system_prompt_text = system_prompt_text

    def build_system_prompt(self, context):
        return self._system_prompt_text


class TeamLeader(BaseAgent):
    """Base class for team leaders. Extends BaseAgent with briefing management and worker spawning."""

    team_name: str = "base_team"
    worker_tools: list[ToolDef] = []

    def __init__(self, provider: LLMProvider, sess=None, db=None):
        super().__init__(provider, sess, db)

    def _get_briefing(self):
        if self.sess and hasattr(self.sess, "team_briefings"):
            return self.sess.team_briefings.get(self.team_name)
        return None

    def _persist_briefing(self):
        """Save current team briefing to DB."""
        if not self.sess or not self.sess.db_path:
            return
        briefing = self._get_briefing()
        if not briefing:
            return
        try:
            db_data = read_db(self.sess.db_path)
            if "team_briefings" not in db_data:
                db_data["team_briefings"] = {}
            db_data["team_briefings"][self.team_name] = briefing.to_dict()
            write_db(db_data, self.sess.db_path)
        except Exception:
            log.exception("Failed to persist briefing for team %s", self.team_name)

    def _all_briefings_text(self) -> str:
        """Render all team briefings for cross-team awareness."""
        if not self.sess or not hasattr(self.sess, "team_briefings"):
            return ""
        lines = []
        for tname, tb in self.sess.team_briefings.items():
            lines.append(tb.render_compact(tname))
        return "\n".join(lines)

    def _build_worker_prompt(self, task: str, extra_context: str, context: dict) -> str:
        """Build a system prompt for a worker agent."""
        binary_name = context.get("binary_name", "unknown")
        arch = context.get("arch", "unknown")

        briefing = self._get_briefing()
        briefing_text = ""
        if briefing and briefing.findings:
            finding_lines = [f"- **{k}**: {v}" for k, v in briefing.findings.items()]
            briefing_text = "**Team findings so far:**\n" + "\n".join(finding_lines)

        parts = [
            f"You are a **senior {self.team_name.replace('_', ' ')} analyst** working a focused sub-task "
            f"on **{binary_name}** ({arch}).",
            "",
            "## OUTPUT STYLE",
            "- Your responses should be short and concise. State findings, not steps.",
            "- NEVER announce upcoming actions (\"Let me first read X, then check Y\"). Tool calls appear in the UI as activity events — narrating them is pure waste. Just call the tool.",
            "- NEVER recap between tool rounds (\"Now I have the full picture\", \"Great, let me summarize\"). Tool results are context; act on them, do not announce them.",
            "- No filler openers (\"Great\", \"Perfect\", \"Excellent\", \"Sure\"). Skip to substance.",
            "- Don't restate what tools just returned — synthesize. Match length to task; no headers for short replies.",
            "- The visible reply is capped at ~4000 chars. Push detail into save_memory and reference the keys.",
            "",
            "BAD:  'Let me read the function. [tool call] Now I see it. I'll check the callers next. [tool call] Now I have the full picture.'",
            "GOOD: '[tool call] [tool call] FUN_x parses length-prefixed blob; called by Y and Z. Details saved to memory[parse_blob_analysis].'",
            "",
            f"**Your task:** {task}",
        ]
        if extra_context:
            parts.append(f"\n**Additional context:** {extra_context}")
        if briefing_text:
            parts.append(f"\n{briefing_text}")

        parts.extend([
            "",
            "**IMPORTANT — Output Budget:** Your response will be truncated to ~4000 chars. "
            "Use save_memory() to persist every important discovery BEFORE writing your final response. "
            "Keep your response concise with references to saved memory keys.",
            "",
            "**Pagination:** Use start_line/max_lines (pseudocode) or offset/limit (disassembly) for large functions.",
            "",
            "**EFFICIENCY:** Never call the same tool with identical arguments twice. "
            "Batch related lookups. If stuck after 3 rounds, summarize what you have and stop.",
        ])

        if self.sess and self.sess.working_memory:
            mem_preview = []
            for k, v in list(self.sess.working_memory.items())[:10]:
                preview = v[:200] + "..." if len(v) > 200 else v
                mem_preview.append(f"- **{k}**: {preview}")
            if mem_preview:
                parts.append("\n**Shared working memory:**\n" + "\n".join(mem_preview))

        return "\n".join(parts)

    def _execute_update_briefing(self, tc_id, args):
        """Handle the update_briefing tool call."""
        briefing = self._get_briefing()
        if not briefing:
            return ToolResult(tc_id, "No briefing available for this team", is_error=True)

        if args.get("summary"):
            briefing.summary = args["summary"]
        if args.get("findings"):
            for k, v in args["findings"].items():
                briefing.findings[k] = v
        if args.get("areas_covered"):
            for area in args["areas_covered"]:
                if area not in briefing.areas_covered:
                    briefing.areas_covered.append(area)
        if args.get("open_questions") is not None:
            briefing.open_questions = args["open_questions"]

        briefing.last_updated = now_iso()
        self._persist_briefing()

        return ToolResult(
            tc_id,
            f"Team briefing updated. Summary: {briefing.summary[:200]}. "
            f"Findings: {len(briefing.findings)}. Open questions: {len(briefing.open_questions)}."
        )

    def _execute_delegate_to_worker(self, tc, context):
        """Spawn a worker agent and run it. Returns (ToolResult, generator of AgentEvents)."""
        task = tc.arguments.get("task", "")
        extra_ctx = tc.arguments.get("context", "")

        worker_prompt = self._build_worker_prompt(task, extra_ctx, context)
        worker = WorkerAgent(
            self.provider, self.sess, self.db,
            worker_name=f"{self.team_name}_worker",
            tools=self.worker_tools,
            system_prompt_text=worker_prompt,
        )
        return worker, task

    def run_streaming(self, messages, context=None):
        """Team leader streaming with worker delegation and briefing management."""
        context = context or {}
        system_prompt = self.build_system_prompt(context)
        conversation = list(messages)
        seen_calls: set[str] = set()

        for round_num in range(MAX_LEADER_ROUNDS):
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
                        yield event
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

            special_names = {"update_briefing", "delegate_to_worker"}
            regular_tools = [tc for tc in pending_tool_calls if tc.name not in special_names]
            briefing_tools = [tc for tc in pending_tool_calls if tc.name == "update_briefing"]
            worker_tools = [tc for tc in pending_tool_calls if tc.name == "delegate_to_worker"]

            tool_results = []
            dupes_this_round = 0

            for tc in regular_tools:
                if tc.name == "report_vulnerability":
                    yield AgentEvent(EventType.VULNERABILITY, tc.arguments)

                call_key = _make_call_key(tc)
                if call_key in seen_calls:
                    dupes_this_round += 1
                    result = ToolResult(
                        tc.id,
                        "Duplicate call — use different arguments or pagination.",
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
                    yield AgentEvent(EventType.TOOL_RESULT, {
                        "tool": result.tool_call_name,
                        "summary": result.content[:200],
                        "is_error": result.is_error,
                    })

            if dupes_this_round >= LOOP_GUARD_MAX_DUPES_PER_ROUND:
                self._append_tool_results(conversation, tool_results)
                yield AgentEvent(EventType.TEXT_DELTA, {
                    "content": "\n\n[Team leader loop guard — summarizing partial findings.]\n\n",
                })
                yield AgentEvent(EventType.DONE, {})
                return

            for tc in briefing_tools:
                result = self._execute_update_briefing(tc.id, tc.arguments)
                result.tool_call_name = tc.name
                tool_results.append(result)
                yield AgentEvent(EventType.TOOL_RESULT, {
                    "tool": "update_briefing",
                    "summary": result.content[:200],
                    "is_error": result.is_error,
                })

            for tc in worker_tools:
                worker, task = self._execute_delegate_to_worker(tc, context)
                worker_name = f"{self.team_name}_worker"

                yield AgentEvent(EventType.AGENT_START, {"agent": worker_name, "task": task})

                sub_messages = [{"role": "user", "content": task}]
                sub_text = ""

                for sub_event in worker.run_streaming(sub_messages, context):
                    if sub_event.type == EventType.TEXT_DELTA:
                        sub_text += sub_event.data.get("content", "")
                        yield sub_event
                    elif sub_event.type in (EventType.TOOL_USE, EventType.TOOL_RESULT, EventType.THINKING):
                        yield sub_event
                    elif sub_event.type == EventType.VULNERABILITY:
                        yield sub_event
                    elif sub_event.type == EventType.DONE:
                        pass

                yield AgentEvent(EventType.AGENT_DONE, {"agent": worker_name})
                tool_results.append(ToolResult(
                    tc.id,
                    f"Worker completed. Response:\n{sub_text[:4000]}",
                ))

            result_map = {r.tool_call_id: r for r in tool_results}
            results_ordered = [result_map[tc.id] for tc in pending_tool_calls if tc.id in result_map]
            self._append_tool_results(conversation, results_ordered if results_ordered else tool_results)

        yield AgentEvent(EventType.DONE, {})
