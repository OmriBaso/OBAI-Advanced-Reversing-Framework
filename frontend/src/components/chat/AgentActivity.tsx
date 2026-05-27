import { useState } from "react";
import type { AgentActivity as ActivityType } from "../../api/types";
import { Wrench, Bot, ChevronDown, ChevronRight, CheckCircle, XCircle, Loader, HelpCircle } from "lucide-react";

interface Props {
  activities: ActivityType[];
  collapsed?: boolean;
}

const TOOL_LABELS: Record<string, string> = {
  read_pseudocode: "Reading function code",
  read_disassembly: "Reading disassembly",
  get_xrefs: "Finding cross-references",
  get_callers: "Finding callers",
  get_callees: "Finding callees",
  get_string_xrefs: "Searching strings",
  get_symbol_xrefs: "Finding global symbol uses",
  get_symbol_info: "Inspecting global symbol",
  get_import_xrefs: "Finding import callers",
  get_cfg: "Analyzing control flow",
  get_call_path: "Tracing call path",
  trace_chain_backwards_from: "Tracing upstream call chain",
  rename_function: "Renaming function",
  rename_variable: "Renaming variable",
  rename_symbol: "Renaming global symbol",
  get_imports: "Listing imports",
  search_functions: "Searching functions",
  list_functions: "Browsing functions",
  list_strings: "Browsing strings",
  list_exports: "Browsing exports",
  get_binary_info: "Reading binary info",
  save_memory: "Saving to memory",
  get_memory: "Reading memory",
  save_finding: "Saving to memory",
  get_findings: "Reading memory",
  explore_paths: "Exploring paths (symbolic)",
  get_path_constraints: "Solving path constraints",
  inspect_function_state: "Inspecting function state",
  report_vulnerability: "Reporting vulnerability",
  submit_exploit: "Submitting exploit",
  delegate_to_team: "Delegating to team",
  delegate_to_agent: "Delegating to team",
  delegate_to_worker: "Spawning worker",
  get_team_briefings: "Reading team briefings",
  update_briefing: "Updating team briefing",
  run_powershell: "Running PowerShell",
  run_csharp: "Running C# code",
  get_system_info: "Getting system info",
  query_ad: "Querying Active Directory",
  list_agents: "Listing agents",
  ask_user: "Asking user",
};

const AGENT_LABELS: Record<string, string> = {
  recon: "Recon Team",
  code_analysis: "Code Analysis Team",
  security: "Security Team",
  recon_worker: "Recon Worker",
  code_analysis_worker: "Code Analysis Worker",
  security_worker: "Security Worker",
  code_analyst: "Code Analyst",
  vuln_scanner: "Vulnerability Scanner",
  exploit_writer: "Exploit Writer",
};

export function AgentActivity({ activities, collapsed: initialCollapsed }: Props) {
  const [collapsed, setCollapsed] = useState(initialCollapsed ?? false);

  if (!activities.length) return null;

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] overflow-hidden text-xs">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center gap-2 px-3 py-1.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
      >
        {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
        <span className="font-medium">
          {activities.length} tool {activities.length === 1 ? "call" : "calls"}
        </span>
      </button>

      {!collapsed && (
        <div className="border-t border-[var(--color-border)] divide-y divide-[var(--color-border-light)]">
          {activities.map((act, i) => (
            <div key={i} className="flex items-center gap-2 px-3 py-1.5">
              {act.type === "tool_start" && (
                <>
                  <Wrench size={11} className="text-[var(--color-accent)] flex-shrink-0" />
                  <span className="text-[var(--color-text-secondary)]">
                    {TOOL_LABELS[act.tool || ""] || act.tool}
                  </span>
                  <div className="w-3 h-3 border border-[var(--color-accent)] border-t-transparent rounded-full animate-spin flex-shrink-0" />
                </>
              )}
              {act.type === "tool_executing" && (
                <>
                  <Loader size={11} className="text-[var(--color-accent)] animate-spin flex-shrink-0" />
                  <span className="text-[var(--color-accent)] font-medium">
                    Running {TOOL_LABELS[act.tool || ""] || act.tool}...
                  </span>
                </>
              )}
              {act.type === "tool_result" && (
                <>
                  {act.is_error ? (
                    <XCircle size={11} className="text-[var(--color-red)] flex-shrink-0" />
                  ) : (
                    <CheckCircle size={11} className="text-[var(--color-green)] flex-shrink-0" />
                  )}
                  <span className="text-[var(--color-text-muted)] truncate">
                    {act.summary || TOOL_LABELS[act.tool || ""] || act.tool}
                  </span>
                </>
              )}
              {act.type === "agent_start" && (
                <>
                  <Bot size={11} className="text-[var(--color-purple)] flex-shrink-0" />
                  <span className="text-[var(--color-purple)] font-medium">
                    {AGENT_LABELS[act.agent || ""] || act.agent}
                  </span>
                  <span className="text-[var(--color-text-muted)] truncate">{act.task}</span>
                </>
              )}
              {act.type === "agent_done" && (
                <>
                  <CheckCircle size={11} className="text-[var(--color-green)] flex-shrink-0" />
                  <span className="text-[var(--color-text-muted)]">
                    {AGENT_LABELS[act.agent || ""] || act.agent} completed
                  </span>
                </>
              )}
              {act.type === "ask_user" && (
                <>
                  <HelpCircle size={11} className="text-[var(--color-yellow)] flex-shrink-0" />
                  <span className="text-[var(--color-yellow)] font-medium">
                    Asking user a question
                  </span>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
