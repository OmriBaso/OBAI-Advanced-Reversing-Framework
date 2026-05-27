import { create } from "zustand";

type Tab = "pseudocode" | "disasm" | "cfg" | "chain" | "imports" | "exports" | "strings" | "search" | "bindiff" | "vulnerabilities";
type Modal = null | "config" | "databases" | "dependencies" | "xrefs" | "callers" | "callees" | "freeRoam" | "agents" | "exportSelect" | "exitSession" | "addBinary";

interface UIState {
  activeTab: Tab;
  activeModal: Modal;
  sidebarWidth: number;
  chatHeight: number;
  funcSearch: string;
  funcFilter: "all" | "named" | "imports";

  pendingSid: string;
  pendingMode: "basic" | "basic_pdb" | "full_map";
  missingDlls: string[];
  pendingImports: PendingImport[];
  filledFromPath: Set<string>;
  uploadedDlls: Set<string>;

  setActiveTab: (tab: Tab) => void;
  openModal: (modal: Modal) => void;
  closeModal: () => void;
  setSidebarWidth: (w: number) => void;
  setChatHeight: (h: number) => void;
  setFuncSearch: (s: string) => void;
  setFuncFilter: (f: "all" | "named" | "imports") => void;
  setDependencyInfo: (sid: string, dlls: string[]) => void;
  setRichDependencyInfo: (sid: string, mode: "basic_pdb" | "full_map", imports: PendingImport[]) => void;
  markDllUploaded: (dll: string) => void;
  markDllsFilledFromPath: (names: string[]) => void;
  clearDependencyInfo: () => void;
}

export interface PendingImport {
  name: string;
  found_at: string | null;
  is_system: boolean;
  size_bytes: number | null;
}

export const useUIStore = create<UIState>((set) => ({
  activeTab: "pseudocode",
  activeModal: null,
  sidebarWidth: 280,
  chatHeight: 340,
  funcSearch: "",
  funcFilter: "all",

  pendingSid: "",
  pendingMode: "basic",
  missingDlls: [],
  pendingImports: [],
  filledFromPath: new Set(),
  uploadedDlls: new Set(),

  setActiveTab: (tab) => set({ activeTab: tab }),
  openModal: (modal) => set({ activeModal: modal }),
  closeModal: () => set({ activeModal: null }),
  setSidebarWidth: (w) => set({ sidebarWidth: w }),
  setChatHeight: (h) => set({ chatHeight: h }),
  setFuncSearch: (s) => set({ funcSearch: s }),
  setFuncFilter: (f) => set({ funcFilter: f }),
  setDependencyInfo: (sid, dlls) =>
    set({
      pendingSid: sid,
      pendingMode: "basic",
      missingDlls: dlls,
      pendingImports: [],
      uploadedDlls: new Set(),
      filledFromPath: new Set(),
    }),
  setRichDependencyInfo: (sid, mode, imports) =>
    set({
      pendingSid: sid,
      pendingMode: mode,
      missingDlls: [],
      pendingImports: imports,
      uploadedDlls: new Set(),
      filledFromPath: new Set(),
    }),
  markDllUploaded: (dll) => set((s) => {
    const next = new Set(s.uploadedDlls);
    next.add(dll);
    return { uploadedDlls: next };
  }),
  markDllsFilledFromPath: (names) => set((s) => {
    const next = new Set(s.filledFromPath);
    for (const n of names) next.add(n);
    return { filledFromPath: next };
  }),
  clearDependencyInfo: () =>
    set({
      pendingSid: "",
      pendingMode: "basic",
      missingDlls: [],
      pendingImports: [],
      uploadedDlls: new Set(),
      filledFromPath: new Set(),
    }),
}));
