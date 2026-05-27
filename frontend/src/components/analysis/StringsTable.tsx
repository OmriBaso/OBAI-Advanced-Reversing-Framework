import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { useState } from "react";
import { ChevronDown, ChevronRight, Loader } from "lucide-react";
import type { StringXrefReference } from "../../api/types";
import { ModuleFilterBar } from "./ModuleFilterBar";

type RefsState = "loading" | "loaded" | "error";

export function StringsTable() {
  const { strings, sid, setSelectedFunction } = useAnalysisStore();
  const { setActiveTab } = useUIStore();
  const [search, setSearch] = useState("");
  const [moduleFilter, setModuleFilter] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [refsByAddr, setRefsByAddr] = useState<Record<string, StringXrefReference[]>>({});
  const [stateByAddr, setStateByAddr] = useState<Record<string, RefsState>>({});

  const filtered = strings.filter((s) => {
    if (moduleFilter && s.module !== moduleFilter) return false;
    return s.text.toLowerCase().includes(search.toLowerCase());
  });

  async function toggleRow(text: string, address: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(address)) next.delete(address);
      else next.add(address);
      return next;
    });

    if (stateByAddr[address]) return;

    setStateByAddr((s) => ({ ...s, [address]: "loading" }));
    try {
      const data = await apiClient.getStringXrefs(sid, text);
      const match = data.find((d) => d.address_hex === address) || data[0];
      setRefsByAddr((r) => ({ ...r, [address]: match?.references ?? [] }));
      setStateByAddr((s) => ({ ...s, [address]: "loaded" }));
    } catch {
      setStateByAddr((s) => ({ ...s, [address]: "error" }));
    }
  }

  function jumpTo(funcName: string) {
    setSelectedFunction(funcName);
    setActiveTab("pseudocode");
  }

  return (
    <div className="h-full flex flex-col">
      <ModuleFilterBar label="Strings for" value={moduleFilter} onChange={setModuleFilter} />
      <div className="p-2 border-b border-[var(--color-border)]">
        <input
          type="text"
          placeholder="Filter strings..."
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
              <th className="px-3 py-2">String</th>
              <th className="px-3 py-2 w-28">Address</th>
              <th className="px-3 py-2 w-16 text-center">XRefs</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((str, i) => {
              const isOpen = expanded.has(str.address_hex);
              const status = stateByAddr[str.address_hex];
              const refs = refsByAddr[str.address_hex];
              const clickable = str.xref_count > 0;

              return (
                <>
                  <tr
                    key={`row-${i}`}
                    onClick={clickable ? () => toggleRow(str.text, str.address_hex) : undefined}
                    className={`border-t border-[var(--color-border-light)] hover:bg-[var(--color-bg-tertiary)] ${
                      clickable ? "cursor-pointer" : ""
                    }`}
                  >
                    <td className="px-3 py-1.5 text-[var(--color-text-muted)]">
                      {clickable &&
                        (isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />)}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[var(--color-text-primary)] truncate max-w-md">
                      {str.text}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[var(--color-text-muted)]">
                      {str.address_hex}
                    </td>
                    <td className="px-3 py-1.5 text-center">
                      {str.xref_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-accent)]">
                          {str.xref_count}
                        </span>
                      )}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr key={`refs-${i}`} className="bg-[var(--color-bg-primary)]">
                      <td colSpan={4} className="px-8 py-2 border-t border-[var(--color-border-light)]">
                        {status === "loading" && (
                          <div className="flex items-center gap-2 text-[var(--color-text-muted)]">
                            <Loader size={12} className="animate-spin" /> Loading references...
                          </div>
                        )}
                        {status === "error" && (
                          <div className="text-[var(--color-red)]">Failed to load references.</div>
                        )}
                        {status === "loaded" && refs && refs.length === 0 && (
                          <div className="text-[var(--color-text-muted)]">
                            {str.xref_count} reference{str.xref_count === 1 ? "" : "s"} from data
                            sections — no containing function.
                          </div>
                        )}
                        {status === "loaded" && refs && refs.length > 0 && (
                          <div className="flex flex-col gap-1">
                            {refs.map((ref, j) => (
                              <button
                                key={j}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  jumpTo(ref.function);
                                }}
                                className="text-left flex items-center gap-3 px-2 py-1 rounded hover:bg-[var(--color-bg-tertiary)] transition-colors"
                              >
                                <span className="font-mono text-xs text-[var(--color-accent)]">
                                  {ref.function}
                                </span>
                                <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                                  {ref.address_hex}
                                </span>
                                <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                                  from {ref.from_address}
                                </span>
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
