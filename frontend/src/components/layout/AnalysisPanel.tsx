import { useUIStore } from "../../stores/uiStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { CodeView } from "../analysis/CodeView";
import { DisassemblyView } from "../analysis/DisassemblyView";
import { CFGGraph } from "../analysis/CFGGraph";
import { CallChainGraph } from "../analysis/CallChainGraph";
import { ImportsTable } from "../analysis/ImportsTable";
import { ExportsTable } from "../analysis/ExportsTable";
import { StringsTable } from "../analysis/StringsTable";
import { CodeSearch } from "../analysis/CodeSearch";
import { BinDiff } from "../analysis/BinDiff";
import { VulnPanel } from "../analysis/VulnPanel";
import { UploadZone } from "../upload/UploadZone";
import { ExternalLink, GitBranch, ArrowUpRight, Loader, Network } from "lucide-react";

const TABS = [
  { id: "pseudocode" as const, label: "Decompiled" },
  { id: "disasm" as const, label: "Disassembly" },
  { id: "cfg" as const, label: "CFG" },
  { id: "chain" as const, label: "Chain" },
  { id: "imports" as const, label: "Imports" },
  { id: "exports" as const, label: "Exports" },
  { id: "strings" as const, label: "Strings" },
  { id: "search" as const, label: "Code Search" },
  { id: "bindiff" as const, label: "Bin Diff" },
  { id: "vulnerabilities" as const, label: "Vulnerabilities" },
];

export function AnalysisPanel() {
  const { activeTab, setActiveTab, openModal } = useUIStore();
  const { sid, selectedFunction, isAnalyzing, analysisStatus } = useAnalysisStore();

  if (!sid && !isAnalyzing) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-lg font-semibold text-[var(--color-text-secondary)] mb-2">
            No Analysis Loaded
          </h2>
          <p className="text-sm text-[var(--color-text-muted)] mb-6">
            Upload a binary or load a saved database to begin.
          </p>
          <UploadZone />
        </div>
      </div>
    );
  }

  if (isAnalyzing) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader size={40} className="text-[var(--color-accent)] animate-spin" />
          <h2 className="text-lg font-semibold text-[var(--color-text-secondary)]">
            Analyzing Binary
          </h2>
          <p className="text-sm text-[var(--color-text-muted)]">
            {analysisStatus || "Please wait..."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
        <div className="flex-1 flex overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-[var(--color-accent)] text-[var(--color-accent)]"
                  : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {selectedFunction && (
          <div className="flex items-center gap-1 px-2">
            <button
              onClick={() => openModal("xrefs")}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
            >
              <ExternalLink size={10} /> XRefs
            </button>
            <button
              onClick={() => openModal("callers")}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
            >
              <ArrowUpRight size={10} /> Callers
            </button>
            <button
              onClick={() => openModal("callees")}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
            >
              <GitBranch size={10} /> Callees
            </button>
            <button
              onClick={() => setActiveTab("chain")}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
              title="Track caller chain backwards"
            >
              <Network size={10} /> Track Chain
            </button>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        {activeTab === "pseudocode" && <CodeView />}
        {activeTab === "disasm" && <DisassemblyView />}
        {activeTab === "cfg" && <CFGGraph />}
        {activeTab === "chain" && <CallChainGraph />}
        {activeTab === "imports" && <ImportsTable />}
        {activeTab === "exports" && <ExportsTable />}
        {activeTab === "strings" && <StringsTable />}
        {activeTab === "bindiff" && <BinDiff />}
        {activeTab === "search" && <CodeSearch />}
        {activeTab === "vulnerabilities" && <VulnPanel />}
      </div>
    </div>
  );
}
