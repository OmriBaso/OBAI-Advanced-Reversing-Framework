"""Tool definitions for the RE agent system.

Each tool is a ToolDef with a name, description, and JSON Schema parameters.
The executor functions are defined here and dispatch to the core engines.
"""

import logging
import threading
from ..agents.providers.base import ToolDef, ToolResult
from ..core.helpers import (
    find_func_addr, get_cached_pseudocode, build_addr_to_name_map,
    resolve_angr_func_addr, addr_str_to_int, resolve_function_module_paths,
)
from ..core.ghidra_engine import (
    ghidra_decompile, ghidra_get_xrefs, ghidra_get_string_xrefs, ghidra_disassemble,
    ghidra_rename_function, ghidra_rename_variable, ghidra_rename_global_symbol,
    ghidra_get_symbol_xrefs, ghidra_get_symbol_info,
)
from ..core.helpers import rename_function_in_db, rename_variable_in_db, rename_symbol_in_db
from ..models.database import read_db as _read_db, write_db as _write_db
from ..core.angr_engine import angr_find_call_path, angr_get_cfg_text, angr_get_cfg_data, angr_call_chain_text
from ..core.angr_symex import symex_explore_paths, symex_get_constraints, symex_inspect_state
from ..models.database import read_db, write_db

log = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = 20000


def _cap_result(tc_id, content, is_error=False, limit=MAX_TOOL_RESULT_CHARS):
    """Return a ToolResult, truncating content if it exceeds the limit."""
    if len(content) > limit:
        content = content[:limit] + (
            f"\n\n[TRUNCATED at {limit} chars — {len(content) - limit} chars omitted. "
            f"Use start_line/max_lines (pseudocode) or offset/limit (disassembly) "
            f"to page through remaining content. Save what you have to save_memory first.]"
        )
    return ToolResult(tc_id, content, is_error)


# ---------------------------------------------------------------------------
# Pending user questions (ask_user tool support)
# ---------------------------------------------------------------------------

_pending_questions: dict[str, dict] = {}
_question_events: dict[str, threading.Event] = {}


def submit_question(question_id: str, question: str):
    """Register a pending question. Called before blocking."""
    _question_events[question_id] = threading.Event()
    _pending_questions[question_id] = {"question": question, "answer": None}


def answer_question(question_id: str, answer: str) -> bool:
    """Provide an answer to a pending question. Unblocks the waiting thread."""
    if question_id not in _pending_questions:
        return False
    _pending_questions[question_id]["answer"] = answer
    _question_events[question_id].set()
    return True


def wait_for_answer(question_id: str, timeout: float = 300) -> str | None:
    """Block until the user answers or timeout. Returns the answer or None."""
    evt = _question_events.get(question_id)
    if not evt:
        return None
    answered = evt.wait(timeout=timeout)
    result = _pending_questions.pop(question_id, {}).get("answer")
    _question_events.pop(question_id, None)
    if not answered:
        return None
    return result


# ---------------------------------------------------------------------------
# Tool Definitions (provider-agnostic)
# ---------------------------------------------------------------------------

READ_PSEUDOCODE = ToolDef(
    name="read_pseudocode",
    description="Decompile and read the pseudocode of a function. Supports pagination for large functions via start_line/max_lines.",
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The name of the function to decompile",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict the function lookup to a specific module (e.g. 'hman.dll'). Only relevant when Full Map Analysis loaded multiple modules and the function name is ambiguous. Omit for the main binary or auto-resolve.",
            },
            "start_line": {
                "type": "integer",
                "description": "Start at this line number (0-indexed, default 0). Use to page through large functions.",
            },
            "max_lines": {
                "type": "integer",
                "description": "Max lines to return (default 0 = all). Use with start_line to page through large functions.",
            },
        },
        "required": ["function_name"],
    },
)

READ_DISASSEMBLY = ToolDef(
    name="read_disassembly",
    description="Get the disassembly listing of a function. Supports pagination via offset/limit for large functions.",
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The name of the function to disassemble",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict the function lookup to a specific module (e.g. 'hman.dll'). Only relevant when Full Map Analysis loaded multiple modules and the function name is ambiguous.",
            },
            "offset": {
                "type": "integer",
                "description": "Start at this instruction index (default 0). Use to page through large functions.",
            },
            "limit": {
                "type": "integer",
                "description": "Max instructions to return (default 200).",
            },
        },
        "required": ["function_name"],
    },
)

GET_XREFS = ToolDef(
    name="get_xrefs",
    description="Get cross-references (callers) to a function. Shows which functions call this one. Same-module only.",
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function to find callers of",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict the function lookup to a specific module (e.g. 'hman.dll'). Cross-module xrefs are not supported — this only finds callers within the same module.",
            },
        },
        "required": ["function_name"],
    },
)

GET_CALLERS = ToolDef(
    name="get_callers",
    description="Get the list of functions that call a given function (via angr call graph).",
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function name to find callers of",
            }
        },
        "required": ["function_name"],
    },
)

GET_CALLEES = ToolDef(
    name="get_callees",
    description="Get the list of functions called by a given function (via angr call graph).",
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function name to find callees of",
            }
        },
        "required": ["function_name"],
    },
)

GET_IMPORT_XREFS = ToolDef(
    name="get_import_xrefs",
    description=(
        "List every function in the binary that calls an imported API (e.g. "
        "'CreateFileW', 'VirtualAlloc', 'memcpy'). Resolves the import by name "
        "to its IAT/thunk address and returns the callers. Use this for taint-source "
        "and sink analysis — 'who calls VirtualAlloc with W|X', 'who reads from the "
        "registry', etc."
    ),
    parameters={
        "type": "object",
        "properties": {
            "import_name": {
                "type": "string",
                "description": "Exact name of the imported API (e.g. 'CreateFileW').",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict to a specific module when the analysis is multi-binary.",
            },
        },
        "required": ["import_name"],
    },
)

GET_SYMBOL_INFO = ToolDef(
    name="get_symbol_info",
    description=(
        "Inspect a GLOBAL symbol — address, kind (data/function/label), Ghidra-assigned "
        "datatype, size, memory section, value, and a hex+ASCII byte preview of its "
        "initial contents. Use this when you see a DAT_xxx (or any global) in pseudocode "
        "and want to know what it actually holds before deciding whether to rename or "
        "what semantics it carries. Everything reported is direct from Ghidra — when "
        "Ghidra has not defined a datatype, `is_defined` is false and `datatype` is null "
        "(a known gap, not a guess)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "symbol_name": {
                "type": "string",
                "description": "Symbol name (e.g. 'DAT_140123000' or a renamed name).",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict to a specific module when multi-module.",
            },
        },
        "required": ["symbol_name"],
    },
)

GET_SYMBOL_XREFS = ToolDef(
    name="get_symbol_xrefs",
    description=(
        "Find every reference (read/write/data) to a GLOBAL symbol — DAT_xxx, "
        "PTR_xxx, named buffer, BSS variable, struct, etc. Returns each "
        "reference's containing function and the address inside that function "
        "where the access happens. Use this AFTER understanding what a global "
        "holds to map out who reads/writes it. Not the same as get_string_xrefs — "
        "that one only covers string-typed data; this one works for any global symbol."
    ),
    parameters={
        "type": "object",
        "properties": {
            "symbol_name": {
                "type": "string",
                "description": "Symbol name (e.g. 'DAT_140123000' or a renamed name like 'g_config_buffer').",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict to a specific module when the analysis is multi-module.",
            },
        },
        "required": ["symbol_name"],
    },
)

GET_STRING_XREFS = ToolDef(
    name="get_string_xrefs",
    description="Search for string references matching a text pattern and find which functions reference them.",
    parameters={
        "type": "object",
        "properties": {
            "search_text": {
                "type": "string",
                "description": "The text to search for in binary strings",
            }
        },
        "required": ["search_text"],
    },
)

GET_CFG = ToolDef(
    name="get_cfg",
    description="Get the control flow graph of a function as structured text showing basic blocks, branches, and conditions.",
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function to get the CFG for",
            }
        },
        "required": ["function_name"],
    },
)

GET_CALL_PATH = ToolDef(
    name="get_call_path",
    description="Find the shortest call path between two functions. Useful for tracing how data/control flows through the binary.",
    parameters={
        "type": "object",
        "properties": {
            "source": {
                "type": "string",
                "description": "Source function name",
            },
            "target": {
                "type": "string",
                "description": "Target function name",
            },
        },
        "required": ["source", "target"],
    },
)

TRACE_CHAIN_BACKWARDS_FROM = ToolDef(
    name="trace_chain_backwards_from",
    description=(
        "Trace the backward call chain from a function — walk through every function that "
        "eventually calls into this one, breadth-first, layer by layer. Each layer is one "
        "call-graph hop: layer 1 is every direct caller, layer 2 is every caller of those, "
        "and so on. All sibling callers within a layer are ALWAYS returned together — the "
        "layer cap never drops siblings mid-layer. Omit max_layers to walk the chain all "
        "the way back to its entry points. Best for sink / data-flow / taint-source analysis. "
        "Prefer this over repeated get_callers calls."
    ),
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The sink function to trace backward from",
            },
            "max_layers": {
                "type": "integer",
                "description": (
                    "Optional. Maximum number of call-graph hops to walk back (1 = direct "
                    "callers only). Omit to walk the entire upstream chain. Each layer "
                    "always includes every sibling caller — this controls depth, not breadth."
                ),
            },
        },
        "required": ["function_name"],
    },
)

GET_IMPORTS = ToolDef(
    name="get_imports",
    description="List all imported functions grouped by library.",
    parameters={
        "type": "object",
        "properties": {},
    },
)

SEARCH_FUNCTIONS = ToolDef(
    name="search_functions",
    description="Search for functions by name pattern (case-insensitive substring match). Returns matching function names and their addresses.",
    parameters={
        "type": "object",
        "properties": {
            "pattern": {
                "type": "string",
                "description": "Substring to search for in function names",
            }
        },
        "required": ["pattern"],
    },
)

LIST_FUNCTIONS = ToolDef(
    name="list_functions",
    description="List all functions discovered in the binary. Can filter by category and paginate through results. Use this to get an overview of the binary's functions.",
    parameters={
        "type": "object",
        "properties": {
            "filter": {
                "type": "string",
                "enum": ["all", "named", "unnamed", "imports"],
                "description": "Filter category: 'all' (default), 'named' (symbols only), 'unnamed' (FUN_/sub_ prefixed), 'imports' (imported functions)",
            },
            "offset": {
                "type": "integer",
                "description": "Start index for pagination (default 0)",
            },
            "limit": {
                "type": "integer",
                "description": "Max functions to return (default 100, max 500)",
            },
        },
    },
)

LIST_STRINGS = ToolDef(
    name="list_strings",
    description="List all strings discovered in the binary. Can filter by text pattern and paginate. Use to find interesting strings like error messages, URLs, registry keys, format strings, etc.",
    parameters={
        "type": "object",
        "properties": {
            "filter": {
                "type": "string",
                "description": "Optional substring filter (case-insensitive). Leave empty to list all strings.",
            },
            "offset": {
                "type": "integer",
                "description": "Start index for pagination (default 0)",
            },
            "limit": {
                "type": "integer",
                "description": "Max strings to return (default 100, max 500)",
            },
        },
    },
)

LIST_EXPORTS = ToolDef(
    name="list_exports",
    description="List all exported functions/symbols from the binary.",
    parameters={
        "type": "object",
        "properties": {},
    },
)

RENAME_FUNCTION = ToolDef(
    name="rename_function",
    description=(
        "Rename a function in the Ghidra project AND in our database. Persistent across "
        "server restarts. Use this once you understand what an unnamed FUN_xxxxxx actually "
        "does — give it a meaningful name like 'ParseAuthRequest' so all future pseudocode "
        "(including call sites in other functions) shows the new name. Rejects external / "
        "thunk / import functions."
    ),
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "Current name of the function to rename.",
            },
            "new_name": {
                "type": "string",
                "description": "New name (valid C identifier: alnum + underscores, not starting with digit).",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict to a specific module (e.g. 'hman.dll') when the name is ambiguous.",
            },
        },
        "required": ["function_name", "new_name"],
    },
)

RENAME_SYMBOL = ToolDef(
    name="rename_symbol",
    description=(
        "Rename a GLOBAL symbol (data references like DAT_140123000, PTR_xxx, "
        "s_xxx, OFF_xxx, unk_xxx). Persistent across server restarts. Use this "
        "once you understand what a global holds — e.g. rename DAT_140123000 to "
        "g_config_buffer. Affects every function that references the symbol."
    ),
    parameters={
        "type": "object",
        "properties": {
            "old_name": {
                "type": "string",
                "description": "Current symbol name (e.g. 'DAT_140123000').",
            },
            "new_name": {
                "type": "string",
                "description": "New name (valid C identifier).",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict to a specific module when the analysis is multi-module.",
            },
        },
        "required": ["old_name", "new_name"],
    },
)

RENAME_VARIABLE = ToolDef(
    name="rename_variable",
    description=(
        "Rename a local variable or parameter inside a function. Persistent. Use this to "
        "give meaningful names to local_NN / param_N once you understand what they hold "
        "(e.g. local_18 -> userInputLength). Only affects that one function's pseudocode."
    ),
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "Function containing the variable.",
            },
            "old_var_name": {
                "type": "string",
                "description": "Current variable name (e.g. 'local_18', 'param_1').",
            },
            "new_var_name": {
                "type": "string",
                "description": "New variable name (valid C identifier).",
            },
            "module": {
                "type": "string",
                "description": "Optional. Restrict to a specific module when the function name is ambiguous.",
            },
        },
        "required": ["function_name", "old_var_name", "new_var_name"],
    },
)

LIST_MODULES = ToolDef(
    name="list_modules",
    description=(
        "List every analyzed module — the main binary and, in Full Map Analysis mode, "
        "each linked DLL that was loaded for cross-module navigation. Use this to discover "
        "which DLLs you can decompile into. Returns module name, whether it's the main "
        "binary, architecture, function count, and symbol-load status."
    ),
    parameters={"type": "object", "properties": {}},
)

GET_BINARY_INFO = ToolDef(
    name="get_binary_info",
    description="Get metadata about the binary being analyzed: filename, architecture, entry point, whether symbols were loaded, section count, total functions, total imports/exports/strings counts.",
    parameters={
        "type": "object",
        "properties": {},
    },
)

REPORT_VULNERABILITY = ToolDef(
    name="report_vulnerability",
    description="Report a discovered vulnerability with structured details.",
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Short name of the vulnerability"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "function": {"type": "string", "description": "Function where the vulnerability was found"},
            "classification": {
                "type": "string",
                "enum": [
                    "arbitrary_write", "arbitrary_read", "buffer_overflow",
                    "integer_overflow", "use_after_free", "race_condition",
                    "info_disclosure", "null_deref", "other",
                ],
            },
            "description": {"type": "string", "description": "Detailed description of the vulnerability"},
        },
        "required": ["name", "severity", "function", "classification", "description"],
    },
)

SUBMIT_EXPLOIT = ToolDef(
    name="submit_exploit",
    description="Submit a generated exploit proof-of-concept.",
    parameters={
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "The exploit code"},
            "language": {"type": "string", "description": "Programming language (c, cpp, python, etc.)"},
            "description": {"type": "string", "description": "What the exploit does"},
        },
        "required": ["code", "language", "description"],
    },
)

SAVE_MEMORY = ToolDef(
    name="save_memory",
    description=(
        "Save any information to persistent working memory. Use for intermediate results, "
        "partial analysis, notes, context you will need later. This survives across all rounds "
        "and is shared with sub-agents. Overwriting an existing key updates it. Use proactively "
        "to avoid losing work if output gets truncated."
    ),
    parameters={
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "Short descriptive label (e.g., 'flag_check_location', 'partial_I_GetTGSTicket_analysis')",
            },
            "content": {
                "type": "string",
                "description": "The information to save — findings, addresses, partial analysis, notes",
            },
        },
        "required": ["key", "content"],
    },
)

GET_MEMORY = ToolDef(
    name="get_memory",
    description="Retrieve all entries currently saved in working memory.",
    parameters={
        "type": "object",
        "properties": {},
    },
)

EXPLORE_PATHS = ToolDef(
    name="explore_paths",
    description=(
        "Symbolically explore execution paths through a function using angr. "
        "Optionally specify a target address to reach and addresses to avoid. "
        "Returns reachable paths with their constraints — useful for understanding "
        "what conditions lead to specific code paths."
    ),
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function to explore",
            },
            "target_address": {
                "type": "string",
                "description": "Optional hex address to try to reach (e.g. '0x180069a00')",
            },
            "avoid_addresses": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of hex addresses to avoid",
            },
            "max_steps": {
                "type": "integer",
                "description": "Max symbolic execution steps (default 500)",
            },
        },
        "required": ["function_name"],
    },
)

GET_PATH_CONSTRAINTS = ToolDef(
    name="get_path_constraints",
    description=(
        "Find what conditions/parameter values are needed to reach a specific address "
        "within a function. Returns simplified symbolic constraints showing what must "
        "hold for the target to be reachable."
    ),
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function containing the target",
            },
            "target_address": {
                "type": "string",
                "description": "Hex address to reach (e.g. '0x180069a00')",
            },
            "max_steps": {
                "type": "integer",
                "description": "Max symbolic execution steps (default 500)",
            },
        },
        "required": ["function_name", "target_address"],
    },
)

INSPECT_FUNCTION_STATE = ToolDef(
    name="inspect_function_state",
    description=(
        "Step through a function symbolically and inspect register/memory state. "
        "Optionally provide concrete argument values to see what happens with specific inputs."
    ),
    parameters={
        "type": "object",
        "properties": {
            "function_name": {
                "type": "string",
                "description": "The function to step through",
            },
            "arg_values": {
                "type": "object",
                "description": "Optional dict of register name -> hex value for concrete args (e.g. {'rcx': '0x1', 'rdx': '0x0'})",
            },
            "steps": {
                "type": "integer",
                "description": "Number of steps to execute (default 50)",
            },
        },
        "required": ["function_name"],
    },
)

DELEGATE_TO_TEAM = ToolDef(
    name="delegate_to_team",
    description=(
        "Delegate a task to a team leader. Each team leader has its own context window and "
        "persistent briefing. Use for any work requiring 2+ tool calls. Always provide specific "
        "function names, addresses, and what to look for. The team leader will save results to "
        "shared memory and update their briefing.\n"
        "Teams:\n"
        "- 'recon': Binary structure, strings, imports, exports, function categorization\n"
        "- 'code_analysis': Deep code understanding, algorithms, data flow, call chains, symbolic execution\n"
        "- 'security': Vulnerability scanning, attack surface, exploit development"
    ),
    parameters={
        "type": "object",
        "properties": {
            "team": {
                "type": "string",
                "enum": ["recon", "code_analysis", "security"],
                "description": "Which team to delegate to",
            },
            "task": {
                "type": "string",
                "description": "Clear, specific description of what the team should do",
            },
            "context": {
                "type": "string",
                "description": "Additional context (function names, addresses, prior findings keys)",
            },
        },
        "required": ["team", "task"],
    },
)

DELEGATE_TO_AGENT = ToolDef(
    name="delegate_to_agent",
    description="(Deprecated — use delegate_to_team instead) Delegate to a sub-agent.",
    parameters={
        "type": "object",
        "properties": {
            "agent": {
                "type": "string",
                "enum": ["code_analyst", "vuln_scanner", "exploit_writer"],
                "description": "Which sub-agent to delegate to",
            },
            "task": {"type": "string", "description": "Task description"},
            "context": {"type": "string", "description": "Additional context"},
        },
        "required": ["agent", "task"],
    },
)

GET_TEAM_BRIEFINGS = ToolDef(
    name="get_team_briefings",
    description="Read all team briefings at once. Shows what each team has done, their findings, and open questions. Cheap and fast.",
    parameters={
        "type": "object",
        "properties": {},
    },
)

UPDATE_BRIEFING = ToolDef(
    name="update_briefing",
    description=(
        "Update your team's briefing. Call this at the end of every task to record what you did. "
        "The orchestrator reads this to understand your team's status."
    ),
    parameters={
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "1-3 sentence overview of what the team has done (replaces previous summary)",
            },
            "findings": {
                "type": "object",
                "description": "Dict of key -> concise finding to add/update in the briefing",
            },
            "areas_covered": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of function names or areas analyzed to add to the covered list",
            },
            "open_questions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of unresolved questions (replaces previous list)",
            },
        },
    },
)

DELEGATE_TO_WORKER = ToolDef(
    name="delegate_to_worker",
    description=(
        "Spawn a focused worker agent for heavy tasks. The worker has its own context window "
        "and will save results to shared memory. Use for: large function analysis, multi-function "
        "tracing, systematic scanning. Always provide specific function names and what to look for."
    ),
    parameters={
        "type": "object",
        "properties": {
            "task": {
                "type": "string",
                "description": "Clear, specific task for the worker",
            },
            "context": {
                "type": "string",
                "description": "Additional context (function addresses, prior findings, what to save)",
            },
        },
        "required": ["task"],
    },
)

ASK_USER = ToolDef(
    name="ask_user",
    description=(
        "Ask the user a clarifying question and wait for their response. Use this when "
        "you are unsure about the user's intent, need to choose between multiple approaches, "
        "or need specific information only the user can provide. The investigation pauses "
        "until the user responds."
    ),
    parameters={
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "The question to ask the user",
            },
        },
        "required": ["question"],
    },
)

# ---------------------------------------------------------------------------
# Tool sets for different agent types
# ---------------------------------------------------------------------------

ANALYSIS_TOOLS = [
    READ_PSEUDOCODE, READ_DISASSEMBLY, GET_XREFS, GET_CALLERS, GET_CALLEES,
    GET_STRING_XREFS, GET_SYMBOL_XREFS, GET_SYMBOL_INFO, GET_IMPORT_XREFS, GET_CFG, GET_CALL_PATH, TRACE_CHAIN_BACKWARDS_FROM,
    GET_IMPORTS, SEARCH_FUNCTIONS,
    LIST_FUNCTIONS, LIST_STRINGS, LIST_EXPORTS, LIST_MODULES, GET_BINARY_INFO,
    EXPLORE_PATHS, GET_PATH_CONSTRAINTS, INSPECT_FUNCTION_STATE,
    RENAME_FUNCTION, RENAME_VARIABLE, RENAME_SYMBOL,
    SAVE_MEMORY, GET_MEMORY,
]

VULN_TOOLS = ANALYSIS_TOOLS + [REPORT_VULNERABILITY]
EXPLOIT_TOOLS = [READ_PSEUDOCODE, SUBMIT_EXPLOIT]

RECON_LEADER_TOOLS = [
    GET_BINARY_INFO, LIST_MODULES, LIST_FUNCTIONS, SEARCH_FUNCTIONS, LIST_STRINGS,
    LIST_EXPORTS, GET_IMPORTS, GET_STRING_XREFS,
    SAVE_MEMORY, GET_MEMORY, UPDATE_BRIEFING,
]

CODE_ANALYSIS_LEADER_TOOLS = ANALYSIS_TOOLS + [
    UPDATE_BRIEFING, DELEGATE_TO_WORKER,
]

SECURITY_LEADER_TOOLS = ANALYSIS_TOOLS + [
    REPORT_VULNERABILITY, SUBMIT_EXPLOIT,
    UPDATE_BRIEFING, DELEGATE_TO_WORKER,
]

WORKER_TOOLS = ANALYSIS_TOOLS

from ..remote.remote_tools import REMOTE_TOOLS, REMOTE_TOOL_NAMES

ORCHESTRATOR_TOOLS = [
    GET_BINARY_INFO, LIST_MODULES, SEARCH_FUNCTIONS, LIST_STRINGS,
    SAVE_MEMORY, GET_MEMORY,
    DELEGATE_TO_TEAM, GET_TEAM_BRIEFINGS, ASK_USER,
] + REMOTE_TOOLS


# ---------------------------------------------------------------------------
# Tool Executors
# ---------------------------------------------------------------------------

def execute_tool(tool_call, sess, db):
    """Execute a tool call and return a ToolResult."""
    name = tool_call.name
    args = tool_call.arguments
    tc_id = tool_call.id

    if name in REMOTE_TOOL_NAMES:
        from ..remote.remote_tools import execute_remote_tool
        return execute_remote_tool(tool_call, sess, db)

    try:
        if name == "read_pseudocode":
            fn = args.get("function_name", "")
            module = args.get("module") or None
            code = get_cached_pseudocode(sess, db, fn, module)
            if not code:
                return ToolResult(tc_id, f"Could not decompile function '{fn}'", is_error=True)
            all_lines = code.split("\n")
            total = len(all_lines)
            start = max(int(args.get("start_line", 0)), 0)
            maxl = int(args.get("max_lines", 0))
            if maxl > 0:
                page = all_lines[start:start + maxl]
            else:
                page = all_lines[start:]
            header = f"Pseudocode for {fn} (lines {start}-{start+len(page)} of {total}):"
            return _cap_result(tc_id, header + "\n```c\n" + "\n".join(page) + "\n```")

        elif name == "read_disassembly":
            fn = args.get("function_name", "")
            module = args.get("module") or None
            mod_name, binary_path, project_name = resolve_function_module_paths(sess, db, fn, module)
            if not mod_name or not binary_path or not project_name:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            func_addr = find_func_addr(db, fn, mod_name)
            if not func_addr:
                return ToolResult(tc_id, f"Function '{fn}' not found in module '{mod_name}'", is_error=True)
            with sess.lock:
                insns = ghidra_disassemble(binary_path, project_name, func_addr)
            total = len(insns)
            offset = max(int(args.get("offset", 0)), 0)
            limit = min(max(int(args.get("limit", 200)), 1), 500)
            page = insns[offset:offset + limit]
            lines = [f"{i['address']}: {i['mnemonic']} {i['op_str']}" for i in page]
            header = f"Disassembly for {mod_name}!{fn} (instructions {offset}-{offset+len(page)} of {total}):"
            return _cap_result(tc_id, header + "\n" + "\n".join(lines))

        elif name == "get_xrefs":
            fn = args.get("function_name", "")
            module = args.get("module") or None
            mod_name, binary_path, project_name = resolve_function_module_paths(sess, db, fn, module)
            if not mod_name or not binary_path or not project_name:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            func_addr = find_func_addr(db, fn, mod_name)
            if not func_addr:
                return ToolResult(tc_id, f"Function '{fn}' not found in module '{mod_name}'", is_error=True)
            with sess.lock:
                xrefs = ghidra_get_xrefs(binary_path, project_name, func_addr)
            if xrefs:
                lines = [f"  - {x['name']} at {x['address_hex']}" for x in xrefs[:20]]
                return _cap_result(tc_id, f"Cross-references to {mod_name}!{fn} ({len(xrefs)} callers):\n" + "\n".join(lines))
            return ToolResult(tc_id, f"No cross-references found for {mod_name}!{fn}.")

        elif name == "get_callers":
            fn = args.get("function_name", "")
            if not sess.angr_cfg:
                return ToolResult(tc_id, "angr CFG not available", is_error=True)
            addr = resolve_angr_func_addr(sess, db, fn)
            if addr is None:
                return ToolResult(tc_id, f"Function '{fn}' not found in call graph", is_error=True)
            name_map = build_addr_to_name_map(db)
            cg = sess.angr_cfg.kb.callgraph
            results = []
            for a in cg.predecessors(addr):
                f = sess.angr_cfg.kb.functions.get(a)
                if f:
                    results.append(name_map.get(a) or f.name or f"sub_{a:x}")
            return ToolResult(tc_id, f"Callers of {fn}: {', '.join(results) if results else 'none found'}")

        elif name == "get_callees":
            fn = args.get("function_name", "")
            if not sess.angr_cfg:
                return ToolResult(tc_id, "angr CFG not available", is_error=True)
            addr = resolve_angr_func_addr(sess, db, fn)
            if addr is None:
                return ToolResult(tc_id, f"Function '{fn}' not found in call graph", is_error=True)
            name_map = build_addr_to_name_map(db)
            cg = sess.angr_cfg.kb.callgraph
            results = []
            for a in cg.successors(addr):
                f = sess.angr_cfg.kb.functions.get(a)
                if f:
                    results.append(name_map.get(a) or f.name or f"sub_{a:x}")
            return ToolResult(tc_id, f"Callees of {fn}: {', '.join(results) if results else 'none found'}")

        elif name == "get_string_xrefs":
            search = args.get("search_text", "")
            if not sess.ghidra_project_name:
                return ToolResult(tc_id, "No Ghidra project available", is_error=True)
            with sess.lock:
                sxrefs = ghidra_get_string_xrefs(sess.binary_path, sess.ghidra_project_name, search)
            if sxrefs:
                lines = []
                for sx in sxrefs[:10]:
                    lines.append(f'  String: "{sx["text"]}" at {sx["address_hex"]}')
                    for r in sx["references"][:5]:
                        lines.append(f"    -> {r['function']} at {r['address_hex']}")
                return _cap_result(tc_id, f'String xrefs for "{search}":\n' + "\n".join(lines))
            return ToolResult(tc_id, f'No strings matching "{search}" found.')

        elif name == "get_cfg":
            fn = args.get("function_name", "")
            cfg_text, error = angr_get_cfg_text(sess, db, fn)
            if cfg_text:
                return _cap_result(tc_id, cfg_text)
            return ToolResult(tc_id, error or f"No CFG available for {fn}", is_error=True)

        elif name == "get_call_path":
            src = args.get("source", "")
            tgt = args.get("target", "")
            path, error = angr_find_call_path(sess, db, src, tgt)
            if path:
                steps = [f"  {i+1}. {s['name']} ({s['address_hex']})" for i, s in enumerate(path)]
                return ToolResult(tc_id, f"Call path ({len(path)} hops):\n" + "\n".join(steps))
            return ToolResult(tc_id, error or "No call path found", is_error=True)

        elif name == "trace_chain_backwards_from":
            fn = args.get("function_name", "")
            if not sess.angr_cfg:
                return ToolResult(tc_id, "angr CFG not available", is_error=True)
            raw_layers = args.get("max_layers")
            try:
                max_layers = max(int(raw_layers), 1) if raw_layers is not None else 10_000
            except (TypeError, ValueError):
                max_layers = 10_000
            text, error = angr_call_chain_text(
                sess, db, fn, max_depth=max_layers, max_nodes=10_000_000
            )
            if text:
                return _cap_result(tc_id, text)
            return ToolResult(tc_id, error or "No call chain found", is_error=True)

        elif name == "get_imports":
            imp_list = db.get("imports", [])
            by_lib = {}
            for imp in imp_list:
                lib = imp.get("library", "unknown")
                by_lib.setdefault(lib, []).append(imp["name"])
            lines = [f"Imports ({len(imp_list)} total):"]
            for lib, names in sorted(by_lib.items()):
                display = ", ".join(names[:20])
                if len(names) > 20:
                    display += f" ... (+{len(names)-20})"
                lines.append(f"  {lib}: {display}")
            return _cap_result(tc_id, "\n".join(lines))

        elif name == "search_functions":
            pattern = args.get("pattern", "").lower()
            all_funcs = db.get("functions", [])
            matches = [(f["name"], f.get("address_hex", "")) for f in all_funcs if pattern in f["name"].lower()]
            if matches:
                lines = [f"  - {n} ({a})" if a else f"  - {n}" for n, a in matches[:100]]
                header = f"Functions matching '{pattern}' ({len(matches)} total"
                if len(matches) > 100:
                    header += f", showing first 100"
                header += "):"
                return _cap_result(tc_id, header + "\n" + "\n".join(lines))
            return ToolResult(tc_id, f"No functions matching '{pattern}'")

        elif name == "list_functions":
            filt = args.get("filter", "all")
            offset = max(int(args.get("offset", 0)), 0)
            limit = min(max(int(args.get("limit", 100)), 1), 500)
            all_funcs = db.get("functions", [])

            if filt == "named":
                funcs = [f for f in all_funcs if not f["name"].startswith(("FUN_", "sub_", "thunk_FUN_"))]
            elif filt == "unnamed":
                funcs = [f for f in all_funcs if f["name"].startswith(("FUN_", "sub_", "thunk_FUN_"))]
            elif filt == "imports":
                funcs = [f for f in all_funcs if f.get("is_external") or f.get("is_thunk")]
            else:
                funcs = all_funcs

            page = funcs[offset:offset + limit]
            lines = [f"  {f['name']}  ({f.get('address_hex', '')})" for f in page]
            header = f"Functions [{filt}] ({len(funcs)} total, showing {offset}..{offset+len(page)}):"
            return _cap_result(tc_id, header + "\n" + "\n".join(lines) if lines else f"No functions found (filter={filt})")

        elif name == "list_strings":
            filt = (args.get("filter") or "").lower()
            offset = max(int(args.get("offset", 0)), 0)
            limit = min(max(int(args.get("limit", 100)), 1), 500)
            all_strings = db.get("strings", [])

            if filt:
                filtered = [s for s in all_strings if filt in (s.get("text") or s.get("value") or "").lower()]
            else:
                filtered = all_strings

            page = filtered[offset:offset + limit]
            lines = []
            for s in page:
                addr = s.get("address_hex", "")
                val = s.get("text") or s.get("value") or ""
                preview = val[:120] + "..." if len(val) > 120 else val
                lines.append(f'  {addr}: "{preview}"')
            header = f"Strings ({len(filtered)} total"
            if filt:
                header += f", filter='{filt}'"
            header += f", showing {offset}..{offset+len(page)}):"
            return _cap_result(tc_id, header + "\n" + "\n".join(lines) if lines else "No strings found")

        elif name == "list_exports":
            exports = db.get("exports", [])
            if exports:
                lines = [f"  - {e['name']} ({e.get('address_hex', '')})" for e in exports[:200]]
                header = f"Exports ({len(exports)} total):"
                if len(exports) > 200:
                    header += " (showing first 200)"
                return _cap_result(tc_id, header + "\n" + "\n".join(lines))
            return ToolResult(tc_id, "No exports found in this binary.")

        elif name == "rename_function":
            fn = args.get("function_name", "")
            new_name = (args.get("new_name") or "").strip()
            module = args.get("module") or None
            if not fn or not new_name:
                return ToolResult(tc_id, "function_name and new_name are required", is_error=True)
            if not new_name.replace("_", "").isalnum() or new_name[0].isdigit():
                return ToolResult(tc_id, "new_name must be a valid identifier", is_error=True)

            mod_name, binary_path, project_name = resolve_function_module_paths(sess, db, fn, module)
            if not mod_name or not binary_path or not project_name:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            func_addr = find_func_addr(db, fn, mod_name)
            if not func_addr:
                return ToolResult(tc_id, f"Function '{fn}' not found in module '{mod_name}'", is_error=True)

            with sess.lock:
                success, errmsg, old_name = ghidra_rename_function(binary_path, project_name, func_addr, new_name)
                if not success:
                    return ToolResult(tc_id, errmsg or "Rename failed", is_error=True)
                if sess.db_path:
                    db_live = _read_db(sess.db_path)
                    rename_function_in_db(db_live, fn, new_name, mod_name)
                    _write_db(db_live, sess.db_path)

            return ToolResult(tc_id, f"Renamed {mod_name}!{old_name or fn} -> {new_name} (persistent).")

        elif name == "rename_symbol":
            old_name = (args.get("old_name") or "").strip()
            new_name = (args.get("new_name") or "").strip()
            module = args.get("module") or None
            if not old_name or not new_name:
                return ToolResult(tc_id, "old_name and new_name are required", is_error=True)
            if not new_name.replace("_", "").isalnum() or new_name[0].isdigit():
                return ToolResult(tc_id, "new_name must be a valid identifier", is_error=True)

            # Resolve binary / project: named module, else main
            binary_path = None
            project_name = None
            resolved_module = module
            if module:
                m = sess.get_module(module) if hasattr(sess, "get_module") else None
                if m and m.binary_path and m.ghidra_project_name:
                    binary_path, project_name = m.binary_path, m.ghidra_project_name
            if not binary_path:
                main = sess.main_module() if hasattr(sess, "main_module") else None
                if main and main.binary_path and main.ghidra_project_name:
                    binary_path, project_name = main.binary_path, main.ghidra_project_name
                    resolved_module = resolved_module or main.name
                elif sess.binary_path and sess.ghidra_project_name:
                    binary_path, project_name = sess.binary_path, sess.ghidra_project_name
            if not binary_path or not project_name:
                return ToolResult(tc_id, "No live Ghidra project for this module", is_error=True)

            with sess.lock:
                success, errmsg, addr = ghidra_rename_global_symbol(
                    binary_path, project_name, old_name, new_name
                )
                if not success:
                    return ToolResult(tc_id, errmsg or "Symbol rename failed", is_error=True)
                if sess.db_path:
                    db_live = _read_db(sess.db_path)
                    rename_symbol_in_db(db_live, resolved_module)
                    _write_db(db_live, sess.db_path)

            return ToolResult(
                tc_id,
                f"Renamed global symbol {old_name} -> {new_name} at {addr or '?'} (persistent)."
            )

        elif name == "rename_variable":
            fn = args.get("function_name", "")
            old_var = (args.get("old_var_name") or "").strip()
            new_var = (args.get("new_var_name") or "").strip()
            module = args.get("module") or None
            if not fn or not old_var or not new_var:
                return ToolResult(tc_id, "function_name, old_var_name, new_var_name are required", is_error=True)
            if not new_var.replace("_", "").isalnum() or new_var[0].isdigit():
                return ToolResult(tc_id, "new_var_name must be a valid identifier", is_error=True)

            mod_name, binary_path, project_name = resolve_function_module_paths(sess, db, fn, module)
            if not mod_name or not binary_path or not project_name:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            func_addr = find_func_addr(db, fn, mod_name)
            if not func_addr:
                return ToolResult(tc_id, f"Function '{fn}' not found in module '{mod_name}'", is_error=True)

            with sess.lock:
                success, errmsg, kind = ghidra_rename_variable(
                    binary_path, project_name, func_addr, old_var, new_var
                )
                if not success:
                    return ToolResult(tc_id, errmsg or "Variable rename failed", is_error=True)
                if sess.db_path:
                    db_live = _read_db(sess.db_path)
                    rename_variable_in_db(db_live, fn, mod_name)
                    _write_db(db_live, sess.db_path)

            return ToolResult(
                tc_id,
                f"Renamed {kind or 'variable'} {old_var} -> {new_var} in {mod_name}!{fn} (persistent)."
            )

        elif name == "get_symbol_info":
            symbol_name = (args.get("symbol_name") or "").strip()
            if not symbol_name:
                return ToolResult(tc_id, "symbol_name is required", is_error=True)
            module = args.get("module") or None

            binary_path = None
            project_name = None
            if module:
                m = sess.get_module(module) if hasattr(sess, "get_module") else None
                if m and m.binary_path and m.ghidra_project_name:
                    binary_path, project_name = m.binary_path, m.ghidra_project_name
            if not binary_path:
                main = sess.main_module() if hasattr(sess, "main_module") else None
                if main and main.binary_path and main.ghidra_project_name:
                    binary_path, project_name = main.binary_path, main.ghidra_project_name
                elif sess.binary_path and sess.ghidra_project_name:
                    binary_path, project_name = sess.binary_path, sess.ghidra_project_name
            if not binary_path or not project_name:
                return ToolResult(tc_id, "No live Ghidra project for this module", is_error=True)

            with sess.lock:
                info, error = ghidra_get_symbol_info(binary_path, project_name, symbol_name)
            if error:
                return ToolResult(tc_id, error, is_error=True)

            lines = [
                f"Symbol: {info['name']}",
                f"  Address:  {info['address_hex'] or '?'}",
                f"  Kind:     {info['kind']}",
                f"  Section:  {info['section'] or '?'}",
            ]
            if info["is_defined"]:
                lines.append(f"  Datatype: {info['datatype']}")
                lines.append(f"  Size:     {info['length']} bytes")
                if info["value"] is not None:
                    lines.append(f"  Value:    {info['value']}")
            else:
                lines.append("  Datatype: (undefined — Ghidra has no Data definition at this address)")
            if info["bytes_hex"]:
                lines.append(f"  Hex:      {info['bytes_hex']}")
                lines.append(f"  ASCII:    {info['bytes_ascii']}")
            return ToolResult(tc_id, "\n".join(lines))

        elif name == "get_import_xrefs":
            import_name = (args.get("import_name") or "").strip()
            if not import_name:
                return ToolResult(tc_id, "import_name is required", is_error=True)
            module = args.get("module") or None

            entry = None
            for imp in db.get("imports", []):
                if imp.get("name") != import_name:
                    continue
                if module is None or imp.get("module") == module:
                    entry = imp
                    break
            if not entry:
                return ToolResult(tc_id, f"Import '{import_name}' not found", is_error=True)

            mod_name = entry.get("module")
            addr_hex = entry.get("address_hex")
            if not addr_hex:
                return ToolResult(tc_id, f"Import '{import_name}' has no address", is_error=True)

            # Resolve module's binary/project
            binary_path = None
            project_name = None
            if mod_name and hasattr(sess, "get_module"):
                m = sess.get_module(mod_name)
                if m and m.binary_path and m.ghidra_project_name:
                    binary_path, project_name = m.binary_path, m.ghidra_project_name
            if not binary_path:
                if sess.binary_path and sess.ghidra_project_name:
                    binary_path, project_name = sess.binary_path, sess.ghidra_project_name
            if not binary_path or not project_name:
                return ToolResult(tc_id, "No live Ghidra project for this module", is_error=True)

            # Cached?
            cache = db.get("imports_xrefs_cache", {}) or {}
            cache_k = f"{mod_name}!{import_name}" if mod_name else import_name
            xrefs = cache.get(cache_k) or cache.get(import_name)
            if not xrefs:
                with sess.lock:
                    xrefs = ghidra_get_xrefs(binary_path, project_name, addr_hex)
                if sess.db_path:
                    db_live = _read_db(sess.db_path)
                    db_live.setdefault("imports_xrefs_cache", {})[cache_k] = xrefs
                    _write_db(db_live, sess.db_path)

            if not xrefs:
                return ToolResult(tc_id, f"No callers of '{import_name}' found.")

            lines = [f"Callers of {import_name} ({len(xrefs)}):"]
            for x in xrefs[:30]:
                lines.append(f"  - {x['name']} at {x['address_hex']}  (from {x.get('from_address', '?')})")
            if len(xrefs) > 30:
                lines.append(f"  ... +{len(xrefs) - 30} more")
            return _cap_result(tc_id, "\n".join(lines))

        elif name == "get_symbol_xrefs":
            symbol_name = (args.get("symbol_name") or "").strip()
            if not symbol_name:
                return ToolResult(tc_id, "symbol_name is required", is_error=True)
            module = args.get("module") or None

            # Resolve binary / project: named module if given, else main
            binary_path = None
            project_name = None
            if module:
                m = sess.get_module(module) if hasattr(sess, "get_module") else None
                if m and m.binary_path and m.ghidra_project_name:
                    binary_path, project_name = m.binary_path, m.ghidra_project_name
            if not binary_path:
                main = sess.main_module() if hasattr(sess, "main_module") else None
                if main and main.binary_path and main.ghidra_project_name:
                    binary_path, project_name = main.binary_path, main.ghidra_project_name
                elif sess.binary_path and sess.ghidra_project_name:
                    binary_path, project_name = sess.binary_path, sess.ghidra_project_name
            if not binary_path or not project_name:
                return ToolResult(tc_id, "No live Ghidra project for this module", is_error=True)

            with sess.lock:
                results, error = ghidra_get_symbol_xrefs(binary_path, project_name, symbol_name)
            if error:
                return ToolResult(tc_id, error, is_error=True)
            if not results:
                return ToolResult(tc_id, f"No references to '{symbol_name}' from inside any function.")

            lines = [f"References to {symbol_name} ({len(results)}):"]
            # group by function for readability
            by_func = {}
            for r in results:
                by_func.setdefault(r["function"], []).append(r)
            for fn_name, refs in by_func.items():
                lines.append(f"  {fn_name}:")
                for r in refs[:10]:
                    lines.append(f"    - {r['from_address']}  ({r['ref_type']})")
                if len(refs) > 10:
                    lines.append(f"    ... +{len(refs) - 10} more references in this function")
            return _cap_result(tc_id, "\n".join(lines))

        elif name == "list_modules":
            modules = db.get("modules", [])
            if not modules:
                bi = db.get("binary_info", {})
                modules = [{
                    "name": bi.get("filename", "main"),
                    "is_main": True,
                    "arch": bi.get("arch", ""),
                    "symbols_loaded": bi.get("symbols_loaded", False),
                }]
            counts = {}
            for f in db.get("functions", []):
                m = f.get("module") or ""
                counts[m] = counts.get(m, 0) + 1
            lines = [f"Modules ({len(modules)}):"]
            for m in modules:
                mname = m.get("name", "?")
                flag = " [main]" if m.get("is_main") else ""
                arch = m.get("arch") or ""
                sym = " (symbols)" if m.get("symbols_loaded") else ""
                cnt = counts.get(mname, 0)
                lines.append(f"  - {mname}{flag}: {cnt} functions, {arch}{sym}")
            if len(modules) == 1:
                lines.append("\nOnly the main binary is loaded. Full Map Analysis must be enabled at upload to load linked DLLs.")
            return _cap_result(tc_id, "\n".join(lines))

        elif name == "get_binary_info":
            info = db.get("binary_info", {})
            funcs = db.get("functions", [])
            named = [f for f in funcs if not f["name"].startswith(("FUN_", "sub_"))]
            parts = [
                f"Filename: {info.get('filename', 'unknown')}",
                f"Architecture: {info.get('arch', 'unknown')}",
                f"Entry point: {info.get('entry_point', 'unknown')}",
                f"Symbols loaded: {info.get('symbols_loaded', False)}",
                f"Total functions: {len(funcs)} ({len(named)} named, {len(funcs)-len(named)} unnamed)",
                f"Total imports: {len(db.get('imports', []))}",
                f"Total exports: {len(db.get('exports', []))}",
                f"Total strings: {len(db.get('strings', []))}",
                f"Vulnerabilities found: {len(db.get('vulnerabilities', []))}",
            ]
            if info.get("sections"):
                parts.append(f"Sections: {', '.join(s.get('name','') for s in info['sections'])}")
            return _cap_result(tc_id, "Binary info:\n" + "\n".join(parts))

        elif name in ("save_memory", "save_finding"):
            key = args.get("key", "")
            content = args.get("content", "")
            if not key or not content:
                return ToolResult(tc_id, "Both 'key' and 'content' are required.", is_error=True)
            sess.working_memory[key] = content
            if sess.db_path:
                try:
                    db_data = read_db(sess.db_path)
                    db_data["working_memory"] = dict(sess.working_memory)
                    write_db(db_data, sess.db_path)
                except Exception:
                    pass
            count = len(sess.working_memory)
            return ToolResult(tc_id, f"Saved to working memory under '{key}'. Memory now has {count} entry(s).")

        elif name in ("get_memory", "get_findings"):
            if not sess.working_memory:
                return ToolResult(tc_id, "Working memory is empty.")
            lines = [f"- **{k}**: {v}" for k, v in sess.working_memory.items()]
            return ToolResult(tc_id, f"Working memory ({len(lines)} entries):\n" + "\n".join(lines))

        elif name == "explore_paths":
            fn = args.get("function_name", "")
            if not sess.angr_project or not sess.angr_cfg:
                return ToolResult(tc_id, "angr project not available for symbolic execution", is_error=True)
            func_addr = addr_str_to_int(find_func_addr(db, fn))
            if func_addr is None:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            target = addr_str_to_int(args.get("target_address")) if args.get("target_address") else None
            avoid = [addr_str_to_int(a) for a in (args.get("avoid_addresses") or []) if addr_str_to_int(a) is not None]
            max_s = int(args.get("max_steps", 500))
            import json
            result = symex_explore_paths(sess.angr_project, sess.angr_cfg, func_addr, target, avoid or None, max_s)
            if result.get("error"):
                return ToolResult(tc_id, f"Symbolic execution error: {result['error']}", is_error=True)
            return _cap_result(tc_id, f"Symbolic exploration of {fn}:\n{json.dumps(result, indent=2)}")

        elif name == "get_path_constraints":
            fn = args.get("function_name", "")
            target_hex = args.get("target_address", "")
            if not sess.angr_project or not sess.angr_cfg:
                return ToolResult(tc_id, "angr project not available for symbolic execution", is_error=True)
            func_addr = addr_str_to_int(find_func_addr(db, fn))
            if func_addr is None:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            target_addr = addr_str_to_int(target_hex)
            if target_addr is None:
                return ToolResult(tc_id, f"Invalid target address: {target_hex}", is_error=True)
            max_s = int(args.get("max_steps", 500))
            import json
            result = symex_get_constraints(sess.angr_project, sess.angr_cfg, func_addr, target_addr, max_s)
            if result.get("error"):
                return ToolResult(tc_id, f"Constraint solving error: {result['error']}", is_error=True)
            return _cap_result(tc_id, f"Path constraints for {fn} -> {target_hex}:\n{json.dumps(result, indent=2)}")

        elif name == "inspect_function_state":
            fn = args.get("function_name", "")
            if not sess.angr_project:
                return ToolResult(tc_id, "angr project not available for symbolic execution", is_error=True)
            func_addr = addr_str_to_int(find_func_addr(db, fn))
            if func_addr is None:
                return ToolResult(tc_id, f"Function '{fn}' not found", is_error=True)
            arg_vals = args.get("arg_values")
            steps = int(args.get("steps", 50))
            import json
            result = symex_inspect_state(sess.angr_project, func_addr, arg_vals, steps)
            if result.get("error"):
                return ToolResult(tc_id, f"State inspection error: {result['error']}", is_error=True)
            return _cap_result(tc_id, f"State inspection of {fn} after {steps} steps:\n{json.dumps(result, indent=2)}")

        elif name == "report_vulnerability":
            return ToolResult(tc_id, "Vulnerability reported successfully.")

        elif name == "submit_exploit":
            return ToolResult(tc_id, "Exploit submitted successfully.")

        elif name in ("delegate_to_team", "delegate_to_agent"):
            return ToolResult(tc_id, "DELEGATE")

        elif name == "get_team_briefings":
            if not hasattr(sess, "team_briefings"):
                return ToolResult(tc_id, "No team briefings available.")
            lines = []
            for tname, tb in sess.team_briefings.items():
                lines.append(tb.render_compact(tname))
                if tb.findings:
                    for k, v in tb.findings.items():
                        preview = v[:300] + "..." if len(v) > 300 else v
                        lines.append(f"  - {k}: {preview}")
                if tb.open_questions:
                    lines.append(f"  Open: {'; '.join(tb.open_questions[:5])}")
                lines.append("")
            return _cap_result(tc_id, "Team Briefings:\n\n" + "\n".join(lines))

        elif name == "update_briefing":
            return ToolResult(tc_id, "UPDATE_BRIEFING")

        elif name == "delegate_to_worker":
            return ToolResult(tc_id, "DELEGATE_WORKER")

        else:
            return ToolResult(tc_id, f"Unknown tool: {name}", is_error=True)

    except Exception as e:
        log.exception("Tool execution error for %s", name)
        return ToolResult(tc_id, f"Tool error: {e}", is_error=True)
