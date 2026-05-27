import { create } from "zustand";
import { apiClient } from "../api/client";
import { useChatStore } from "./chatStore";
import type {
  BinaryFunction,
  Import,
  Export,
  BinaryString,
  Vulnerability,
  ModuleInfo,
} from "../api/types";

// Persist the current sid so a page refresh resumes the session. The browser-side
// sid is cleared ONLY when the backend says "Invalid session" — never on refresh.
const SID_KEY = "obai_sid";
const persistSid = (sid: string) => {
  try {
    if (sid) localStorage.setItem(SID_KEY, sid);
    else localStorage.removeItem(SID_KEY);
  } catch {
    /* localStorage unavailable; non-fatal */
  }
};
const readPersistedSid = (): string => {
  try {
    return localStorage.getItem(SID_KEY) || "";
  } catch {
    return "";
  }
};

const isInvalidSessionError = (e: unknown): boolean => {
  const msg = e instanceof Error ? e.message : String(e || "");
  return /invalid session/i.test(msg) || /session not found/i.test(msg);
};

interface AnalysisState {
  sid: string;
  filename: string;
  arch: string;
  symbolsLoaded: boolean;

  modules: ModuleInfo[];
  moduleFilter: string;          // "" = all modules, otherwise module name
  functions: BinaryFunction[];
  imports: Import[];
  exports: Export[];
  strings: BinaryString[];
  vulnerabilities: Vulnerability[];

  selectedFunction: string;
  selectedFunctionModule: string;
  pseudocodeVersion: number;
  loading: boolean;
  isAnalyzing: boolean;
  analysisStatus: string;

  setSid: (sid: string) => void;
  setAnalysisInfo: (info: {
    filename: string;
    arch: string;
    symbols_loaded: boolean;
  }) => void;
  setSelectedFunction: (name: string, module?: string) => void;
  setModuleFilter: (m: string) => void;
  loadAllData: (sid: string) => Promise<void>;
  runAnalysis: (pendingSid: string) => Promise<void>;
  refreshVulnerabilities: () => Promise<void>;
  renameFunction: (oldName: string, newName: string, module?: string) => Promise<void>;
  renameVariable: (funcName: string, oldVar: string, newVar: string, module?: string) => Promise<void>;
  renameSymbol: (oldName: string, newName: string, module?: string) => Promise<void>;
  restoreSession: () => Promise<void>;
  reset: () => void;
}

export const useAnalysisStore = create<AnalysisState>((set, get) => ({
  sid: "",
  filename: "",
  arch: "",
  symbolsLoaded: false,

  modules: [],
  moduleFilter: "",
  functions: [],
  imports: [],
  exports: [],
  strings: [],
  vulnerabilities: [],

  selectedFunction: "",
  selectedFunctionModule: "",
  pseudocodeVersion: 0,
  loading: false,
  isAnalyzing: false,
  analysisStatus: "",

  setSid: (sid) => {
    persistSid(sid);
    set({ sid });
  },

  setAnalysisInfo: (info) =>
    set({
      filename: info.filename,
      arch: info.arch,
      symbolsLoaded: info.symbols_loaded,
    }),

  setSelectedFunction: (name, module) => {
    if (!name) {
      set({ selectedFunction: "", selectedFunctionModule: "" });
      return;
    }
    // If module wasn't given, derive it from the function entry so cross-module
    // jumps (e.g. clicking a node in the chain graph) target the right module.
    let resolved = module ?? "";
    if (!resolved) {
      const entry = get().functions.find((f) => f.name === name);
      if (entry?.module) resolved = entry.module;
    }
    set({ selectedFunction: name, selectedFunctionModule: resolved });
  },

  setModuleFilter: (m) => set({ moduleFilter: m }),

  runAnalysis: async (pendingSid: string) => {
    set({ isAnalyzing: true, analysisStatus: "Running Ghidra analysis..." });
    try {
      const analysis = await apiClient.startAnalysis(pendingSid);
      set({
        sid: analysis.analysis_id,
        filename: analysis.filename,
        arch: analysis.arch,
        symbolsLoaded: analysis.symbols_loaded,
        analysisStatus: "Loading data...",
      });
      await get().loadAllData(analysis.analysis_id);
    } catch (e: unknown) {
      set({ analysisStatus: `Error: ${e instanceof Error ? e.message : "Analysis failed"}` });
    } finally {
      set({ isAnalyzing: false, analysisStatus: "" });
    }
  },

  loadAllData: async (sid) => {
    persistSid(sid);
    set({ loading: true, sid });
    try {
      const [functions, imports, exports, strings, vulnerabilities, modules] =
        await Promise.all([
          apiClient.getFunctions(sid),
          apiClient.getImports(sid),
          apiClient.getExports(sid),
          apiClient.getStrings(sid),
          apiClient.getVulnerabilities(sid),
          apiClient.listModules(sid).catch(() => [] as ModuleInfo[]),
        ]);
      set({ functions, imports, exports, strings, vulnerabilities, modules, moduleFilter: "" });

      const chatStore = useChatStore.getState();
      await chatStore.refreshChats(sid);
      const latest = useChatStore.getState().chats[0];
      if (latest) {
        await chatStore.loadChat(sid, latest.chat_id).catch(() => chatStore.newChat());
      } else {
        chatStore.newChat();
      }
    } finally {
      set({ loading: false });
    }
  },

  refreshVulnerabilities: async () => {
    const { sid } = get();
    if (!sid) return;
    const vulns = await apiClient.getVulnerabilities(sid);
    set({ vulnerabilities: vulns });
  },

  renameFunction: async (oldName, newName, module) => {
    const { sid } = get();
    if (!sid || !oldName || !newName || oldName === newName) return;
    const result = await apiClient.renameFunction(sid, oldName, newName, module);
    set((s) => {
      const functions = s.functions.map((f) =>
        f.name === oldName && (!result.module || f.module === result.module)
          ? { ...f, name: result.new_name }
          : f
      );
      const selectedFunction =
        s.selectedFunction === oldName ? result.new_name : s.selectedFunction;
      return {
        functions,
        selectedFunction,
        pseudocodeVersion: s.pseudocodeVersion + 1,
      };
    });
  },

  renameVariable: async (funcName, oldVar, newVar, module) => {
    const { sid } = get();
    if (!sid || !funcName || !oldVar || !newVar || oldVar === newVar) return;
    await apiClient.renameVariable(sid, funcName, oldVar, newVar, module);
    // Force a pseudocode refetch — backend invalidated the cache for this function
    set((s) => ({ pseudocodeVersion: s.pseudocodeVersion + 1 }));
  },

  renameSymbol: async (oldName, newName, module) => {
    const { sid } = get();
    if (!sid || !oldName || !newName || oldName === newName) return;
    await apiClient.renameSymbol(sid, oldName, newName, module);
    // Backend invalidated the module's pseudocode + disasm caches — refetch
    set((s) => ({ pseudocodeVersion: s.pseudocodeVersion + 1 }));
  },

  restoreSession: async () => {
    const saved = readPersistedSid();
    if (!saved) return;
    // Optimistically restore the sid so the UI shows the analysis view immediately.
    set({ sid: saved });
    try {
      await get().loadAllData(saved);
    } catch (e) {
      // Backend will return "Invalid session" if the server forgot the sid
      // (TTL reaped, restart with no DB, etc.). Only in that case do we
      // clear local state — network errors should NOT log the user out.
      if (isInvalidSessionError(e)) {
        get().reset();
      } else {
        // Leave the sid in place; the user can retry / the heartbeat may recover.
        set({ loading: false });
      }
    }
  },

  reset: () => {
    persistSid("");
    set({
      sid: "",
      filename: "",
      arch: "",
      symbolsLoaded: false,
      modules: [],
      moduleFilter: "",
      functions: [],
      imports: [],
      exports: [],
      strings: [],
      vulnerabilities: [],
      selectedFunction: "",
      selectedFunctionModule: "",
      pseudocodeVersion: 0,
      loading: false,
      isAnalyzing: false,
      analysisStatus: "",
    });
  },
}));
