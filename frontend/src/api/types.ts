export interface ApiResponse<T = unknown> {
  ok: boolean;
  data: T;
  error?: string;
}

export interface BinaryFunction {
  name: string;
  address_hex: string;
  size: number;
  is_import: boolean;
  is_named: boolean;
  module?: string;
}

export interface ModuleInfo {
  name: string;
  is_main?: boolean;
  arch?: string;
  symbols_loaded?: boolean;
  n_functions?: number;
  binary_path?: string;
  ghidra_project_name?: string;
}

export interface Import {
  name: string;
  library: string;
  address_hex: string;
  module?: string;
}

export interface Export {
  name: string;
  address_hex: string;
  module?: string;
}

export interface BinaryString {
  text: string;
  address_hex: string;
  xref_count: number;
  module?: string;
}

export interface Vulnerability {
  id: string;
  name: string;
  function: string;
  classification: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  discovered_at: string;
  exploit_code: string | null;
}

export interface XRef {
  name: string;
  address_hex: string;
  ref_type?: string;
  from_address?: string;
  is_import?: boolean;
}

export interface StringXrefReference {
  function: string;
  address_hex: string;
  from_address: string;
}

export interface StringXrefMatch {
  text: string;
  address_hex: string;
  references: StringXrefReference[];
}

export interface DisasmInstruction {
  address: string;
  bytes: string;
  mnemonic: string;
  op_str: string;
  label: string;
  type: string;
}

export interface CFGData {
  nodes: Array<{ data: { id: string; label: string; type: string } }>;
  edges: Array<{ data: { source: string; target: string } }>;
}

export interface CallChainNode {
  data: {
    id: string;
    label: string;
    name: string;
    address_hex: string;
    is_root: boolean;
    is_import: boolean;
  };
}

export interface CallChainData {
  nodes: CallChainNode[];
  edges: Array<{ data: { source: string; target: string } }>;
  root: string;
  depth_reached: number;
  truncated: boolean;
  direction: "backward" | "forward";
}

export interface AnalysisInfo {
  analysis_id: string;
  filename: string;
  n_functions: number;
  n_imports: number;
  n_exports: number;
  n_strings: number;
  arch: string;
  symbols_loaded: boolean;
  missing_dlls?: string[];
  from_db?: boolean;
}

export interface DatabaseEntry {
  filename: string;
  path: string;
  binary_name: string;
  arch: string;
  symbols_loaded: boolean;
  n_functions: number;
  n_vulnerabilities: number;
  created_at: string;
  schema: number;
}

export interface ProviderConfig {
  api_key?: string;
  model?: string;
  base_url?: string;
}

export interface AppConfig {
  active_provider: string;
  providers: Record<string, ProviderConfig>;
}

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp?: string;
  agentActivities?: AgentActivity[];
  thinkingText?: string;
}

export interface ChatSummary {
  chat_id: string;
  created_at: string;
  last_updated: string;
  message_count: number;
  preview: string;
}

export interface ChatHistory {
  chat_id: string;
  messages: ChatMessage[];
  current_function?: string;
  context_function_names?: string[];
  created_at?: string;
}

export interface AgentActivity {
  type: "tool_start" | "tool_executing" | "tool_result" | "agent_start" | "agent_done" | "ask_user";
  tool?: string;
  agent?: string;
  task?: string;
  summary?: string;
  is_error?: boolean;
  question?: string;
}

export type SSEEventType =
  | "text_delta"
  | "thinking"
  | "tool_use"
  | "tool_result"
  | "agent_start"
  | "agent_done"
  | "vulnerability"
  | "ask_user"
  | "done"
  | "error";
