"""AI tool definitions and executors for remote agent interaction."""

import logging
from ..agents.providers.base import ToolDef, ToolResult
from ..agents.tools import MAX_TOOL_RESULT_CHARS, _cap_result
from . import agent_manager as mgr

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------

LIST_AGENTS = ToolDef(
    name="list_agents",
    description=(
        "List all connected remote investigation agents. Shows hostname, domain, "
        "user, IP addresses, OS, and whether the agent is running elevated. "
        "Use this first to discover which machines are available for remote operations."
    ),
    parameters={
        "type": "object",
        "properties": {},
    },
)

RUN_POWERSHELL = ToolDef(
    name="run_powershell",
    description=(
        "Execute a PowerShell command or script on a remote agent. "
        "The agent hosts a full PowerShell runtime with access to all modules installed on the target. "
        "Use this for AD queries (Get-ADUser, Get-ADGroup, Get-GPO, etc.), system recon, "
        "file operations, registry access, service enumeration, event log queries, "
        "network diagnostics, and any other Windows administration task. "
        "Returns stdout output and any errors."
    ),
    parameters={
        "type": "object",
        "properties": {
            "agent_id": {
                "type": "string",
                "description": "ID of the target agent (from list_agents)",
            },
            "command": {
                "type": "string",
                "description": "PowerShell command or script to execute",
            },
            "timeout": {
                "type": "integer",
                "description": "Max execution time in seconds (default 120)",
            },
        },
        "required": ["agent_id", "command"],
    },
)

RUN_CSHARP = ToolDef(
    name="run_csharp",
    description=(
        "Compile and execute C# code on a remote agent using Roslyn scripting. "
        "The code has access to System, System.IO, System.Linq, System.Net, System.Text.Json, "
        "System.Diagnostics, System.Runtime.InteropServices, Microsoft.Win32, and more. "
        "Use for complex operations that benefit from compiled code: P/Invoke calls, "
        "COM interop, custom binary parsing, performance-sensitive operations. "
        "Returns the script's return value and any Console.WriteLine output."
    ),
    parameters={
        "type": "object",
        "properties": {
            "agent_id": {
                "type": "string",
                "description": "ID of the target agent (from list_agents)",
            },
            "code": {
                "type": "string",
                "description": "C# code to compile and execute (Roslyn script format — top-level statements, last expression is return value)",
            },
            "timeout": {
                "type": "integer",
                "description": "Max execution time in seconds (default 120)",
            },
        },
        "required": ["agent_id", "code"],
    },
)

GET_SYSTEM_INFO = ToolDef(
    name="get_system_info",
    description=(
        "Get structured system information from a remote agent: hostname, domain, OS, "
        "architecture, IP addresses, network interfaces, drives, top processes by memory, "
        "relevant environment variables, elevation status. "
        "Use this as a first step when investigating a new machine."
    ),
    parameters={
        "type": "object",
        "properties": {
            "agent_id": {
                "type": "string",
                "description": "ID of the target agent (from list_agents)",
            },
        },
        "required": ["agent_id"],
    },
)

QUERY_AD = ToolDef(
    name="query_ad",
    description=(
        "Run a pre-built Active Directory query on a remote agent. "
        "Available query_type values:\n"
        "  - domain_info: Get domain metadata (naming context, forest, functional level)\n"
        "  - users: Enumerate domain users (with optional name filter)\n"
        "  - groups: Enumerate domain groups (with optional name filter)\n"
        "  - computers: Enumerate domain computers (with optional name filter)\n"
        "  - ous: Enumerate organizational units\n"
        "  - gpos: Enumerate Group Policy Objects\n"
        "  - domain_admins: List members of Domain Admins group\n"
        "  - enterprise_admins: List members of Enterprise Admins group\n"
        "  - domain_controllers: List all domain controllers\n"
        "  - spns: Find accounts with Service Principal Names set\n"
        "  - kerberoastable: Find kerberoastable accounts (SPN set, not disabled)\n"
        "  - asreproastable: Find AS-REP roastable accounts (no pre-auth required)\n"
        "  - trusts: Enumerate domain trusts\n"
        "  - custom_ldap: Run a custom LDAP filter (pass the filter in 'command')\n"
        "\nResults are returned as structured JSON."
    ),
    parameters={
        "type": "object",
        "properties": {
            "agent_id": {
                "type": "string",
                "description": "ID of the target agent (from list_agents)",
            },
            "query_type": {
                "type": "string",
                "enum": [
                    "domain_info", "users", "groups", "computers", "ous", "gpos",
                    "domain_admins", "enterprise_admins", "domain_controllers",
                    "spns", "kerberoastable", "asreproastable", "trusts", "custom_ldap",
                ],
                "description": "Type of AD query to run",
            },
            "filter": {
                "type": "string",
                "description": "Optional name filter for users/groups/computers queries",
            },
            "ldap_filter": {
                "type": "string",
                "description": "Custom LDAP filter (only for query_type='custom_ldap')",
            },
        },
        "required": ["agent_id", "query_type"],
    },
)

# All remote tools as a list
REMOTE_TOOLS = [LIST_AGENTS, RUN_POWERSHELL, RUN_CSHARP, GET_SYSTEM_INFO, QUERY_AD]

# Set of remote tool names for dispatch routing
REMOTE_TOOL_NAMES = {t.name for t in REMOTE_TOOLS}


# ---------------------------------------------------------------------------
# Tool Executor
# ---------------------------------------------------------------------------

def execute_remote_tool(tool_call, sess=None, db=None):
    """Execute a remote agent tool call and return a ToolResult."""
    name = tool_call.name
    args = tool_call.arguments
    tc_id = tool_call.id

    try:
        if name == "list_agents":
            agents = mgr.list_alive_agents()
            if not agents:
                return ToolResult(tc_id, "No remote agents are currently connected.")

            lines = [f"Connected agents ({len(agents)}):"]
            for a in agents:
                elevated = " [ELEVATED]" if a.get("is_elevated") else ""
                ips = ", ".join(a.get("ip_addresses", []))
                lines.append(
                    f"  - {a['agent_id']}: {a.get('domain', '')}\\{a.get('username', '')} "
                    f"@ {a.get('hostname', '')} ({ips}) "
                    f"OS: {a.get('os_version', '')}{elevated}"
                )
            return ToolResult(tc_id, "\n".join(lines))

        elif name == "run_powershell":
            agent_id = args.get("agent_id", "")
            command = args.get("command", "")
            timeout = int(args.get("timeout", 120))

            if not agent_id or not command:
                return ToolResult(tc_id, "agent_id and command are required", is_error=True)

            return _submit_and_wait(tc_id, agent_id, "powershell", command, timeout)

        elif name == "run_csharp":
            agent_id = args.get("agent_id", "")
            code = args.get("code", "")
            timeout = int(args.get("timeout", 120))

            if not agent_id or not code:
                return ToolResult(tc_id, "agent_id and code are required", is_error=True)

            return _submit_and_wait(tc_id, agent_id, "csharp", code, timeout)

        elif name == "get_system_info":
            agent_id = args.get("agent_id", "")
            if not agent_id:
                return ToolResult(tc_id, "agent_id is required", is_error=True)

            return _submit_and_wait(tc_id, agent_id, "system_info", "", 60)

        elif name == "query_ad":
            agent_id = args.get("agent_id", "")
            query_type = args.get("query_type", "domain_info")
            name_filter = args.get("filter", "")
            ldap_filter = args.get("ldap_filter", "")

            if not agent_id:
                return ToolResult(tc_id, "agent_id is required", is_error=True)

            command = ldap_filter if query_type == "custom_ldap" else ""
            params = {"query_type": query_type}
            if name_filter:
                params["filter"] = name_filter

            return _submit_and_wait(tc_id, agent_id, "ad_query", command, 120, params)

        else:
            return ToolResult(tc_id, f"Unknown remote tool: {name}", is_error=True)

    except Exception as e:
        log.exception("Remote tool error for %s", name)
        return ToolResult(tc_id, f"Remote tool error: {e}", is_error=True)


def _submit_and_wait(tc_id, agent_id, task_type, command, timeout, parameters=None):
    """Submit a task to an agent and block until the result comes back."""
    agent = mgr.get_agent(agent_id)
    if not agent:
        return ToolResult(tc_id, f"Agent {agent_id} is not connected", is_error=True)

    try:
        task_id = mgr.submit_task(
            agent_id, task_type, command,
            timeout=timeout, parameters=parameters,
        )
    except ValueError as e:
        return ToolResult(tc_id, str(e), is_error=True)

    result = mgr.wait_for_result(task_id, timeout=timeout + 30)
    if result is None:
        return ToolResult(
            tc_id,
            f"Agent {agent_id} did not respond within {timeout}s (task: {task_id})",
            is_error=True,
        )

    output = result.get("output", "")
    error = result.get("error")
    success = result.get("success", False)
    exec_ms = result.get("execution_time_ms", 0)

    text = output
    if error:
        text += f"\n\n[Error] {error}" if text else f"Error: {error}"
    text += f"\n\n(executed in {exec_ms}ms on {agent.hostname})"

    return _cap_result(tc_id, text, is_error=not success)
