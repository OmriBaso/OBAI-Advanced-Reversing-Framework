import type { ApiResponse, Vulnerability, StringXrefMatch, ChatSummary, ChatHistory, CallChainData, ModuleInfo } from "./types";

function modQuery(module?: string) {
  return module ? `?module=${encodeURIComponent(module)}` : "";
}

const BASE = "";

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, options);
  const json: ApiResponse<T> = await resp.json();
  if (!json.ok) throw new Error(json.error || "Request failed");
  return json.data;
}

function GET<T>(path: string): Promise<T> {
  return api<T>(path);
}

function POST<T>(path: string, body?: unknown): Promise<T> {
  return api<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function UPLOAD<T>(path: string, formData: FormData): Promise<T> {
  return api<T>(path, { method: "POST", body: formData });
}

export const apiClient = {
  addBinary: (sid: string, file: File, mode: "basic" | "basic_pdb" | "full_map" = "basic") => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("mode", mode);
    return UPLOAD<{
      module: {
        name: string;
        is_main: boolean;
        arch: string;
        symbols_loaded: boolean;
        binary_path: string;
        ghidra_project_name: string;
      };
      mode: string;
      n_functions: number;
      n_imports: number;
      n_exports: number;
      n_strings: number;
    }>(`/api/analysis/${sid}/add-binary`, fd);
  },

  upload: (file: File, mode: "basic" | "basic_pdb" | "full_map" = "basic") => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("mode", mode);
    return UPLOAD<{
      analysis_id: string;
      filename: string;
      mode: "basic" | "basic_pdb" | "full_map";
      missing_dlls?: string[];
      imports?: Array<{
        name: string;
        found_at: string | null;
        is_system: boolean;
        size_bytes: number | null;
      }>;
    }>("/api/upload", fd);
  },

  fillFromPath: (
    sid: string,
    imports: Array<{ name: string; found_at: string }>,
    overwrite = false
  ) =>
    POST<{
      copied: Array<{ name: string; path: string }>;
      skipped: Array<{ name: string; reason: string }>;
      errors: Array<{ name: string; reason: string }>;
      pending_libraries: string[];
    }>(`/api/fill-from-path/${sid}`, { imports, overwrite }),

  uploadLibrary: (sid: string, file: File, dllName: string) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("dll_name", dllName);
    return UPLOAD<{ dll_name: string; filename: string }>(
      `/api/upload-library/${sid}`,
      fd
    );
  },

  startAnalysis: (sid: string) =>
    POST<{
      analysis_id: string;
      filename: string;
      n_functions: number;
      n_imports: number;
      n_exports: number;
      n_strings: number;
      arch: string;
      symbols_loaded: boolean;
    }>(`/api/start-analysis/${sid}`),

  listDatabases: () =>
    GET<
      Array<{
        filename: string;
        binary_name: string;
        arch: string;
        symbols_loaded: boolean;
        n_functions: number;
        n_vulnerabilities: number;
        created_at: string;
      }>
    >("/api/databases"),

  loadDatabase: (filename: string) =>
    POST<{
      analysis_id: string;
      filename: string;
      n_functions: number;
      n_imports: number;
      n_exports: number;
      n_strings: number;
      arch: string;
      symbols_loaded: boolean;
      from_db: boolean;
    }>("/api/load-db", { filename }),

  listModules: (sid: string) =>
    GET<ModuleInfo[]>(`/api/analysis/${sid}/modules`),

  getFunctions: (sid: string) =>
    GET<
      Array<{
        name: string;
        address_hex: string;
        size: number;
        is_import: boolean;
        is_named: boolean;
        module?: string;
      }>
    >(`/api/analysis/${sid}/functions`),

  getImports: (sid: string) =>
    GET<Array<{ name: string; library: string; address_hex: string }>>(
      `/api/analysis/${sid}/imports`
    ),

  getExports: (sid: string) =>
    GET<Array<{ name: string; address_hex: string }>>(
      `/api/analysis/${sid}/exports`
    ),

  getStrings: (sid: string) =>
    GET<Array<{ text: string; address_hex: string; xref_count: number }>>(
      `/api/analysis/${sid}/strings`
    ),

  getPseudocode: (sid: string, funcName: string, module?: string) =>
    GET<{ function: string; module?: string; pseudocode: string }>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/pseudocode${modQuery(module)}`
    ),

  getDisasm: (sid: string, funcName: string, module?: string) =>
    GET<{ function: string; module?: string; instructions: Array<Record<string, string>> }>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/disasm${modQuery(module)}`
    ),

  getCfg: (sid: string, funcName: string, module?: string) =>
    GET<{ nodes: unknown[]; edges: unknown[] }>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/cfg${modQuery(module)}`
    ),

  getXrefs: (sid: string, funcName: string, module?: string) =>
    GET<
      Array<{
        name: string;
        address_hex: string;
        ref_type: string;
        from_address: string;
      }>
    >(`/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/xrefs${modQuery(module)}`),

  getBinDiffSummary: (sid: string, baseModule: string, compareModule: string) =>
    GET<{
      base_module: string;
      compare_module: string;
      total_base: number;
      total_compare: number;
      diff: Array<{
        name: string;
        status: "removed" | "added" | "size_diff" | "same_size" | "unchanged" | "changed";
        base_address: string | null;
        base_size: number | null;
        compare_address: string | null;
        compare_size: number | null;
      }>;
    }>(
      `/api/analysis/${sid}/diff/${encodeURIComponent(baseModule)}/${encodeURIComponent(compareModule)}`
    ),

  getBinDiffFunction: (
    sid: string,
    baseModule: string,
    compareModule: string,
    funcName: string
  ) =>
    GET<{
      function: string;
      base_module: string;
      compare_module: string;
      base_insns: Array<{ address: string; mnemonic: string; op_str: string; normalized: string }>;
      compare_insns: Array<{ address: string; mnemonic: string; op_str: string; normalized: string }>;
      ops: Array<{
        tag: "equal" | "replace" | "insert" | "delete";
        base_start: number;
        base_end: number;
        compare_start: number;
        compare_end: number;
      }>;
      identical: boolean;
    }>(
      `/api/analysis/${sid}/diff/${encodeURIComponent(baseModule)}/${encodeURIComponent(
        compareModule
      )}/functions/${encodeURIComponent(funcName)}`
    ),

  getImportXrefs: (sid: string, importName: string, module?: string) =>
    GET<
      Array<{
        name: string;
        address_hex: string;
        ref_type: string;
        from_address: string;
      }>
    >(`/api/analysis/${sid}/imports/${encodeURIComponent(importName)}/xrefs${modQuery(module)}`),

  getStringXrefs: (sid: string, search: string) =>
    POST<StringXrefMatch[]>(`/api/analysis/${sid}/strings/xrefs`, { search }),

  getCallers: (sid: string, funcName: string) =>
    GET<Array<{ name: string; address_hex: string; is_import: boolean }>>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/callers`
    ),

  getCallees: (sid: string, funcName: string) =>
    GET<Array<{ name: string; address_hex: string; is_import: boolean }>>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/callees`
    ),

  getFunctionVariables: (sid: string, funcName: string, module?: string) =>
    GET<{
      function: string;
      module?: string;
      params: Array<{ name: string; type: string; ordinal: number }>;
      locals: Array<{ name: string; type: string }>;
    }>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/variables${modQuery(module)}`
    ),

  renameFunction: (sid: string, funcName: string, newName: string, module?: string) =>
    POST<{ old_name: string; new_name: string; module: string; address_hex: string }>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/rename`,
      { new_name: newName, module: module || undefined }
    ),

  renameVariable: (
    sid: string,
    funcName: string,
    oldVarName: string,
    newVarName: string,
    module?: string
  ) =>
    POST<{ function: string; module: string; old_var_name: string; new_var_name: string; kind: string }>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(funcName)}/rename-variable`,
      { old_var_name: oldVarName, new_var_name: newVarName, module: module || undefined }
    ),

  renameSymbol: (sid: string, oldName: string, newName: string, module?: string) =>
    POST<{ old_name: string; new_name: string; module: string; address_hex: string | null }>(
      `/api/analysis/${sid}/symbols/rename`,
      { old_name: oldName, new_name: newName, module: module || undefined }
    ),

  grepFunctions: (
    sid: string,
    pattern: string,
    opts?: { module?: string; case_sensitive?: boolean; max_results?: number; max_decompile_budget?: number }
  ) =>
    POST<{
      matches: Array<{
        module: string;
        function: string;
        address_hex: string;
        lines: Array<{ line_no: number; text: string; is_match: boolean }>;
      }>;
      scanned: number;
      total_in_scope: number;
      decompiled: number;
      budget_exhausted: boolean;
      early_stop: boolean;
      pattern: string;
    }>(`/api/analysis/${sid}/grep-functions`, { pattern, ...opts }),

  getCallChain: (
    sid: string,
    funcName: string,
    direction: "backward" | "forward" = "backward",
    maxDepth = 8,
    maxNodes = 300
  ) =>
    GET<CallChainData>(
      `/api/analysis/${sid}/functions/${encodeURIComponent(
        funcName
      )}/call-chain?direction=${direction}&max_depth=${maxDepth}&max_nodes=${maxNodes}`
    ),

  getVulnerabilities: (sid: string) =>
    GET<Vulnerability[]>(`/api/analysis/${sid}/vulnerabilities`),

  getConfig: () =>
    GET<{
      active_provider: string;
      providers: Record<string, Record<string, string>>;
    }>("/api/config"),

  setConfig: (cfg: Record<string, unknown>) => POST<unknown>("/api/config", cfg),

  chatReset: (sid: string, chatId: string) =>
    POST<{ reset: boolean }>(`/api/analysis/${sid}/chat/reset`, {
      chat_id: chatId,
    }),

  listChats: (sid: string) =>
    GET<ChatSummary[]>(`/api/analysis/${sid}/chats`),

  getChat: (sid: string, chatId: string) =>
    GET<ChatHistory>(`/api/analysis/${sid}/chats/${chatId}`),

  exportAnalysis: async (sid: string) => {
    const resp = await fetch(`/api/analysis/${sid}/export`, { method: "POST" });
    if (!resp.ok) throw new Error("Export failed");
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download =
      resp.headers.get("Content-Disposition")?.split("filename=")[1] ||
      "decompiled.zip";
    a.click();
    URL.revokeObjectURL(url);
  },

  getRemoteAgents: () =>
    GET<{
      agents: Array<{
        agent_id: string;
        hostname: string;
        domain: string;
        username: string;
        os_version: string;
        ip_addresses: string[];
        is_elevated: boolean;
        alive: boolean;
        connected_seconds: number;
      }>;
      count: number;
    }>("/api/remote/agents"),

  disconnectAgent: (agentId: string) =>
    api<{ disconnected: boolean }>(`/api/remote/${agentId}`, { method: "DELETE" }),
};
