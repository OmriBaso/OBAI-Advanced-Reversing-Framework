"""Orchestrator agent: pure coordinator that delegates to team leaders."""

import uuid
import logging
from typing import Generator

from .base import BaseAgent, _make_call_key, LOOP_GUARD_MAX_DUPES_PER_ROUND
from .teams import ReconLeader, CodeAnalysisLeader, SecurityLeader
from .tools import ORCHESTRATOR_TOOLS, execute_tool, submit_question, wait_for_answer
from .providers.base import (
    LLMProvider, AgentEvent, EventType,
    ToolCall, ToolResult, LLMResponse,
)

log = logging.getLogger(__name__)

MAX_ORCHESTRATOR_ROUNDS = 20

AGENT_TO_TEAM = {
    "code_analyst": "code_analysis",
    "vuln_scanner": "security",
    "exploit_writer": "security",
}


class OrchestratorAgent(BaseAgent):
    name = "orchestrator"
    tools = ORCHESTRATOR_TOOLS

    def __init__(self, provider: LLMProvider, sess=None, db=None):
        super().__init__(provider, sess, db)
        self.team_leaders = {
            "recon": ReconLeader(provider, sess, db),
            "code_analysis": CodeAnalysisLeader(provider, sess, db),
            "security": SecurityLeader(provider, sess, db),
        }

    def build_system_prompt(self, context: dict) -> str:
        binary_name = context.get("binary_name", "unknown")
        arch = context.get("arch", "unknown")
        current_func = context.get("current_function", "")
        current_code = context.get("current_code", "")

        sections = [
            f"You are a **senior reverse-engineering lead** coordinating the analysis of **{binary_name}** ({arch}).",
            "",
            "## OUTPUT STYLE",
            "- Your responses should be short and concise. State results and decisions directly, not a running commentary on your thought process.",
            "- NEVER announce upcoming actions (\"Let me check X\", \"I'll delegate to Y\"). Tool calls appear in the UI as activity events — narrating them is pure waste. Just call the tool.",
            "- NEVER recap between tool rounds (\"Now I have the full picture\", \"Great, let me summarize what we found\", \"Now that I understand X...\"). Team reports are context; act on them, do not announce them.",
            "- No filler openers (\"Great\", \"Perfect\", \"Excellent\", \"Sure\"). Skip to substance.",
            "- Don't restate what teams just reported — synthesize for the user's final answer; stay silent between intermediate rounds.",
            "- Match response length to the task: a simple question gets a one-line answer, not a header structure.",
            "- End-of-turn: one or two sentences when appropriate. Findings + what's next. Nothing else.",
            "",
            "BAD:  'Let me check that function. [tool call] Great, now I see it handles auth. I'll look at callers next. [tool call] Now I have the full picture — the function validates the password using memcmp.'",
            "GOOD: '[tool call] [tool call] Password check at FUN_140001234 line 42 uses memcmp on user bytes — uncontrolled length, buffer-overread vector.'",
            "",
            "## YOUR ROLE: COORDINATOR",
            "",
            "You manage three specialized teams. You PLAN, DELEGATE, and SYNTHESIZE.",
            "You do NOT read pseudocode, disassembly, or CFGs yourself — that is team work.",
            "",
            "**Your workflow:**",
            "1. Read team briefings to understand current knowledge",
            "2. Break the user's question into focused sub-tasks",
            "3. Delegate each sub-task to the right team via delegate_to_team",
            "4. Synthesize team responses into a clear answer for the user",
            "",
            "## YOUR TEAMS",
            "",
            "**Recon Team** (`recon`): Binary structure, strings, imports, exports, function categorization.",
            "  Ask them: 'What functions deal with X?', 'Find strings related to Y', 'Map the binary structure'",
            "",
            "**Code Analysis Team** (`code_analysis`): Deep code understanding, algorithms, data flow, symbolic execution.",
            "  Ask them: 'How does function X work?', 'Trace the call chain from A to B', 'What conditions reach address Z?'",
            "",
            "**Security Team** (`security`): Vulnerability scanning, attack surface, exploit development.",
            "  Ask them: 'Is this function vulnerable to X?', 'Find buffer overflows in area Y', 'Write an exploit for Z'",
            "",
            "## YOUR TOOLS",
            "",
            "**Delegation:**",
            "- **delegate_to_team(team, task, context)**: Send a task to a team leader. Be SPECIFIC:",
            "  - GOOD: 'Analyze KdcDmsaTgsReqWorker focusing on the authorization check at the 0x200000 flag. "
            "Save findings to memory key dmsa_authz_analysis.'",
            "  - BAD: 'Analyze the DMSA subsystem' (too vague)",
            "  - GOOD: 'Find all functions related to certificate validation. Categorize them by: "
            "parsing, chain building, revocation checking.'",
            "  - BAD: 'Look at certificates'",
            "",
            "**Briefings:**",
            "- **get_team_briefings()**: Read all team briefings (compact summaries of what each team knows)",
            "",
            "**Quick lookups (for simple questions — no delegation needed):**",
            "- **get_binary_info**: Binary metadata",
            "- **search_functions**: Search by name pattern",
            "- **list_strings**: Search/browse strings",
            "",
            "**User interaction:**",
            "- **ask_user(question)**: Ask the user for clarification",
            "- **save_memory / get_memory**: Cross-team shared working memory",
        ]

        if current_func and current_func != "(none)":
            sections.append(f"\nThe user is currently viewing **{current_func}**.")
            if current_code and not current_code.startswith("//"):
                code_preview = current_code[:2000] + "..." if len(current_code) > 2000 else current_code
                sections.append(f"Decompiled pseudocode:\n```c\n{code_preview}\n```")

        funcs = context.get("available_functions", [])
        func_count = len(funcs)
        named = [f for f in funcs if not f.startswith("sub_") and not f.startswith("FUN_")]
        sections.append(
            f"\n**Binary overview:** {func_count} total functions "
            f"({len(named)} named, {func_count - len(named)} unnamed)."
        )

        modules = context.get("modules", []) or []
        if len(modules) > 1:
            sections.extend([
                "",
                f"**Full Map Analysis is ACTIVE — {len(modules)} modules loaded:** "
                + ", ".join(modules),
                "Functions in linked DLLs can be decompiled too. Pass `module=\"<dll_name>\"` "
                "to read_pseudocode / read_disassembly / get_xrefs when a function name is "
                "ambiguous across modules. Use list_modules for a count breakdown per module.",
            ])

        str_count = context.get("string_count", 0)
        export_count = context.get("export_count", 0)
        imp_summary = context.get("imports_summary", "")
        if str_count:
            sections.append(f"Strings: {str_count}")
        if export_count:
            sections.append(f"Exports: {export_count}")
        if imp_summary:
            sections.append(f"Imports: {imp_summary}")

        # Team briefings
        if self.sess and hasattr(self.sess, "team_briefings"):
            sections.append("\n## TEAM BRIEFINGS")
            any_active = False
            for tname, tb in self.sess.team_briefings.items():
                compact = tb.render_compact(tname)
                sections.append(compact)
                if tb.findings:
                    any_active = True
                    for k, v in list(tb.findings.items())[:5]:
                        preview = v[:200] + "..." if len(v) > 200 else v
                        sections.append(f"  - {k}: {preview}")
                    if len(tb.findings) > 5:
                        sections.append(f"  ... and {len(tb.findings) - 5} more findings")
                if tb.open_questions:
                    sections.append(f"  Open: {'; '.join(tb.open_questions[:3])}")
                sections.append("")

            if not any_active:
                sections.append("(No teams have been activated yet. Delegate tasks to get started.)")

        # Shared working memory (compact)
        if self.sess and self.sess.working_memory:
            sections.append("## SHARED WORKING MEMORY")
            for k, v in list(self.sess.working_memory.items())[:10]:
                preview = v[:150] + "..." if len(v) > 150 else v
                sections.append(f"- **{k}**: {preview}")
            if len(self.sess.working_memory) > 10:
                sections.append(f"... and {len(self.sess.working_memory) - 10} more entries. Use get_memory() to see all.")

        sections.extend([
            "",
            "## GUIDELINES",
            "",
            "**When to delegate:** Any question requiring code reading, analysis, or scanning.",
            "**When to act directly:** Binary metadata, function name search, string lookup, user clarification.",
            "",
            "**Cross-team coordination:**",
            "- For 'How does X work? Is it vulnerable?': First delegate to code_analysis, then security.",
            "- Security team can read code_analysis briefing for context — mention this in the task.",
            "- Recon team should always be the first to run on a new binary.",
            "",
            "**Clarifying questions:** Use ask_user when unsure about intent or approach.",
            "",
            "**When to stop:** If a team reports they're stuck, present partial findings to the user "
            "and ask for guidance rather than retrying.",
            "",
            "**EFFICIENCY:**",
            "- NEVER call the same tool with identical arguments twice.",
            "- Read team briefings before delegating — they may already have the answer.",
            "- One well-written delegation is better than three vague ones.",
        ])

        # Remote investigation agents
        from ..remote import agent_manager as remote_mgr
        live_agents = remote_mgr.list_alive_agents()
        if live_agents:
            sections.extend([
                "",
                "## REMOTE INVESTIGATION AGENTS",
                f"{len(live_agents)} remote agent(s) connected.",
                "Tools: list_agents, run_powershell, run_csharp, get_system_info, query_ad",
            ])
            for a in live_agents:
                elevated = " [ADMIN]" if a.get("is_elevated") else ""
                ips = ", ".join(a.get("ip_addresses", [])[:3])
                sections.append(
                    f"  - **{a['agent_id']}**: {a.get('domain', '')}\\{a.get('username', '')} "
                    f"@ {a.get('hostname', '')} ({ips}){elevated}"
                )

        return "\n\n".join(sections)

    def _resolve_team(self, tc):
        """Resolve team name from either delegate_to_team or legacy delegate_to_agent."""
        if tc.name == "delegate_to_team":
            return tc.arguments.get("team", "")
        elif tc.name == "delegate_to_agent":
            agent_name = tc.arguments.get("agent", "")
            return AGENT_TO_TEAM.get(agent_name, agent_name)
        return ""

    def run_streaming(self, messages, context=None):
        """Orchestrator streaming with team leader delegation and loop guard."""
        context = context or {}
        system_prompt = self.build_system_prompt(context)
        conversation = list(messages)
        seen_calls: set[str] = set()

        for round_num in range(MAX_ORCHESTRATOR_ROUNDS):
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

            delegation_names = {"delegate_to_team", "delegate_to_agent"}
            special_names = delegation_names | {"ask_user"}
            regular_tools = [tc for tc in pending_tool_calls if tc.name not in special_names]
            delegation_tools = [tc for tc in pending_tool_calls if tc.name in delegation_names]
            ask_user_tools = [tc for tc in pending_tool_calls if tc.name == "ask_user"]

            tool_results = []
            dupes_this_round = 0

            for tc in regular_tools:
                call_key = _make_call_key(tc)
                if call_key in seen_calls:
                    dupes_this_round += 1
                    log.warning("Loop guard: duplicate call %s in orchestrator round %d", tc.name, round_num)
                    result = ToolResult(
                        tc.id,
                        "You already called this tool with identical arguments. "
                        "Try different arguments or check team briefings.",
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
                log.warning("Loop guard: %d dupes in orchestrator round %d — forcing stop",
                            dupes_this_round, round_num)
                yield AgentEvent(EventType.TEXT_DELTA, {
                    "content": "\n\n[Detected repeated tool calls — summarizing what I have.]\n\n",
                })
                self._append_tool_results(conversation, tool_results)
                yield AgentEvent(EventType.DONE, {})
                return

            for tc in ask_user_tools:
                question = tc.arguments.get("question", "")
                question_id = str(uuid.uuid4())
                submit_question(question_id, question)
                yield AgentEvent(EventType.ASK_USER, {
                    "question": question,
                    "question_id": question_id,
                })
                answer = wait_for_answer(question_id, timeout=300)
                if answer is None:
                    answer = "(The user did not respond in time.)"
                tool_results.append(ToolResult(tc.id, f"User response: {answer}"))

            for tc in delegation_tools:
                team_name = self._resolve_team(tc)
                task = tc.arguments.get("task", "")
                extra_ctx = tc.arguments.get("context", "")

                leader = self.team_leaders.get(team_name)
                if not leader:
                    tool_results.append(ToolResult(tc.id, f"Unknown team: {team_name}", is_error=True))
                    continue

                yield AgentEvent(EventType.AGENT_START, {"agent": team_name, "task": task})

                sub_context = dict(context)
                sub_context["task"] = task
                sub_context["extra_context"] = extra_ctx

                sub_messages = [{"role": "user", "content": task}]
                sub_text = ""

                for sub_event in leader.run_streaming(sub_messages, sub_context):
                    if sub_event.type == EventType.TEXT_DELTA:
                        sub_text += sub_event.data.get("content", "")
                        yield sub_event
                    elif sub_event.type in (EventType.TOOL_USE, EventType.TOOL_RESULT, EventType.THINKING):
                        yield sub_event
                    elif sub_event.type == EventType.VULNERABILITY:
                        yield sub_event
                    elif sub_event.type in (EventType.AGENT_START, EventType.AGENT_DONE):
                        yield sub_event
                    elif sub_event.type == EventType.DONE:
                        pass

                yield AgentEvent(EventType.AGENT_DONE, {"agent": team_name})

                briefing = leader._get_briefing()
                briefing_summary = ""
                if briefing and briefing.summary:
                    briefing_summary = f"\nTeam briefing: {briefing.summary}"

                tool_results.append(ToolResult(
                    tc.id,
                    f"Team {team_name} completed. Response:\n{sub_text[:4000]}{briefing_summary}",
                ))

            result_map = {r.tool_call_id: r for r in tool_results}
            results_ordered = [result_map[tc.id] for tc in pending_tool_calls if tc.id in result_map]

            self._append_tool_results(conversation, results_ordered if results_ordered else tool_results)

        yield AgentEvent(EventType.DONE, {})

    def run(self, messages, context=None):
        """Synchronous orchestrator run with team delegation and loop guard."""
        context = context or {}
        system_prompt = self.build_system_prompt(context)
        conversation = list(messages)
        collected_text = ""
        all_vulns = []
        seen_calls: set[str] = set()

        for round_num in range(MAX_ORCHESTRATOR_ROUNDS):
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

            delegation_names = {"delegate_to_team", "delegate_to_agent"}
            special_names = delegation_names | {"ask_user"}
            regular_tools = [tc for tc in response.tool_calls if tc.name not in special_names]
            delegation_tools = [tc for tc in response.tool_calls if tc.name in delegation_names]
            ask_user_tools = [tc for tc in response.tool_calls if tc.name == "ask_user"]

            tool_results = []
            dupes_this_round = 0

            for tc in regular_tools:
                call_key = _make_call_key(tc)
                if call_key in seen_calls:
                    dupes_this_round += 1
                    result = ToolResult(tc.id, "Duplicate call.", is_error=True)
                    result.tool_call_name = tc.name
                    tool_results.append(result)
                else:
                    seen_calls.add(call_key)
                    result = execute_tool(tc, self.sess, self.db)
                    result.tool_call_name = tc.name
                    tool_results.append(result)

            if dupes_this_round >= LOOP_GUARD_MAX_DUPES_PER_ROUND:
                collected_text += "\n\n[Loop guard — summarizing partial findings.]\n\n"
                break

            for tc in ask_user_tools:
                tool_results.append(ToolResult(tc.id, "(ask_user is only supported in streaming mode)"))

            for tc in delegation_tools:
                team_name = self._resolve_team(tc)
                task = tc.arguments.get("task", "")
                extra_ctx = tc.arguments.get("context", "")

                leader = self.team_leaders.get(team_name)
                if not leader:
                    tool_results.append(ToolResult(tc.id, f"Unknown team: {team_name}", is_error=True))
                    continue

                sub_context = dict(context)
                sub_context["task"] = task
                sub_context["extra_context"] = extra_ctx

                sub_response = leader.run([{"role": "user", "content": task}], sub_context)
                if sub_response.usage and sub_response.usage.get("vulnerabilities"):
                    all_vulns.extend(sub_response.usage["vulnerabilities"])

                tool_results.append(ToolResult(
                    tc.id,
                    f"Team {team_name} response:\n{sub_response.text[:4000]}",
                ))

            result_map = {r.tool_call_id: r for r in tool_results}
            results_ordered = [result_map[tc.id] for tc in response.tool_calls if tc.id in result_map]
            self._append_tool_results(conversation, results_ordered if results_ordered else tool_results)

        result = LLMResponse(text=collected_text, stop_reason="end_turn")
        result.usage = {"vulnerabilities": all_vulns}
        return result
