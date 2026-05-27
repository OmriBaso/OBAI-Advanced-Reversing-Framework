import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { useState } from "react";
import { ChevronDown, ChevronRight, Loader } from "lucide-react";
import { ModuleFilterBar } from "./ModuleFilterBar";

interface ImportXref {
  name: string;
  address_hex: string;
  ref_type: string;
  from_address: string;
}

type RefsState = "loading" | "loaded" | "error";

export function ImportsTable() {
  const { sid, imports, setSelectedFunction } = useAnalysisStore();
  const { setActiveTab } = useUIStore();
  const [search, setSearch] = useState("");
  const [moduleFilter, setModuleFilter] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [refsByKey, setRefsByKey] = useState<Record<string, ImportXref[]>>({});
  const [stateByKey, setStateByKey] = useState<Record<string, RefsState>>({});

  const filtered = imports.filter((i) => {
    if (moduleFilter && i.module !== moduleFilter) return false;
    return (
      i.name.toLowerCase().includes(search.toLowerCase()) ||
      i.library.toLowerCase().includes(search.toLowerCase())
    );
  });

  const keyFor = (name: string, module?: string) => `${module || ""}::${name}`;

  async function toggleRow(name: string, module?: string) {
    const key = keyFor(name, module);
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

    if (stateByKey[key]) return;

    setStateByKey((s) => ({ ...s, [key]: "loading" }));
    try {
      const data = await apiClient.getImportXrefs(sid, name, module);
      setRefsByKey((r) => ({ ...r, [key]: data }));
      setStateByKey((s) => ({ ...s, [key]: "loaded" }));
    } catch {
      setStateByKey((s) => ({ ...s, [key]: "error" }));
    }
  }

  function jumpTo(funcName: string, module?: string) {
    setSelectedFunction(funcName, module);
    setActiveTab("pseudocode");
  }

  return (
    <div className="h-full flex flex-col">
      <ModuleFilterBar label="Imports for" value={moduleFilter} onChange={setModuleFilter} />
      <div className="p-2 border-b border-[var(--color-border)]">
        <input
          type="text"
          placeholder="Filter imports..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full px-3 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)]"
        />
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-[var(--color-bg-secondary)]">
            <tr className="text-left text-[var(--color-text-muted)]">
              <th className="px-3 py-2 w-6"></th>
              <th className="px-3 py-2">Function</th>
              <th className="px-3 py-2">Library</th>
              <th className="px-3 py-2 w-28">Address</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((imp, i) => {
              const key = keyFor(imp.name, imp.module);
              const isOpen = expanded.has(key);
              const status = stateByKey[key];
              const refs = refsByKey[key];

              return (
                <>
                  <tr
                    key={`row-${i}`}
                    onClick={() => toggleRow(imp.name, imp.module)}
                    className="border-t border-[var(--color-border-light)] hover:bg-[var(--color-bg-tertiary)] cursor-pointer"
                  >
                    <td className="px-3 py-1.5 text-[var(--color-text-muted)]">
                      {isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[var(--color-text-primary)]">
                      {imp.name}
                    </td>
                    <td className="px-3 py-1.5 text-[var(--color-text-secondary)]">
                      {imp.library}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[var(--color-text-muted)]">
                      {imp.address_hex}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr key={`refs-${i}`} className="bg-[var(--color-bg-primary)]">
                      <td colSpan={4} className="px-8 py-2 border-t border-[var(--color-border-light)]">
                        {status === "loading" && (
                          <div className="flex items-center gap-2 text-[var(--color-text-muted)]">
                            <Loader size={12} className="animate-spin" /> Loading callers...
                          </div>
                        )}
                        {status === "error" && (
                          <div className="text-[var(--color-red)]">Failed to load callers.</div>
                        )}
                        {status === "loaded" && refs && refs.length === 0 && (
                          <div className="text-[var(--color-text-muted)]">
                            No callers found — this import isn't referenced from any function.
                          </div>
                        )}
                        {status === "loaded" && refs && refs.length > 0 && (
                          <div className="flex flex-col gap-1">
                            <div className="text-[10px] text-[var(--color-text-muted)] mb-1">
                              {refs.length} caller{refs.length === 1 ? "" : "s"}:
                            </div>
                            {refs.map((ref, j) => (
                              <button
                                key={j}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  jumpTo(ref.name, imp.module);
                                }}
                                className="text-left flex items-center gap-3 px-2 py-1 rounded hover:bg-[var(--color-bg-tertiary)] transition-colors"
                              >
                                <span className="font-mono text-xs text-[var(--color-accent)]">
                                  {ref.name}
                                </span>
                                <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                                  {ref.address_hex}
                                </span>
                                <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                                  from {ref.from_address}
                                </span>
                                {ref.ref_type && (
                                  <span className="text-[9px] text-[var(--color-text-muted)]">
                                    {ref.ref_type}
                                  </span>
                                )}
                              </button>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
