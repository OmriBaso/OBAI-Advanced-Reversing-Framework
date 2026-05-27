import { useEffect, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { X } from "lucide-react";

interface XRefEntry {
  name: string;
  address_hex: string;
  ref_type?: string;
  from_address?: string;
  is_import?: boolean;
}

export function XRefModal() {
  const { sid, selectedFunction, selectedFunctionModule, setSelectedFunction } = useAnalysisStore();
  const { activeModal, closeModal } = useUIStore();
  const [entries, setEntries] = useState<XRefEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const title =
    activeModal === "xrefs" ? "Cross References" :
    activeModal === "callers" ? "Callers" : "Callees";

  useEffect(() => {
    if (!sid || !selectedFunction) return;

    setLoading(true);
    const fetcher =
      activeModal === "xrefs"
        ? apiClient.getXrefs(sid, selectedFunction, selectedFunctionModule || undefined)
        : activeModal === "callers"
        ? apiClient.getCallers(sid, selectedFunction)
        : apiClient.getCallees(sid, selectedFunction);

    fetcher
      .then((data) => setEntries(data as XRefEntry[]))
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [sid, selectedFunction, selectedFunctionModule, activeModal]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeModal}>
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[500px] max-h-[70vh] flex flex-col shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold">
            {title} — <span className="text-[var(--color-accent)] font-mono">{selectedFunction}</span>
          </h3>
          <button onClick={closeModal} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8 text-sm text-[var(--color-text-secondary)]">
              Loading...
            </div>
          ) : entries.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-sm text-[var(--color-text-muted)]">
              No {title.toLowerCase()} found.
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-light)]">
              {entries.map((entry, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setSelectedFunction(entry.name);
                    closeModal();
                  }}
                  className="w-full text-left px-4 py-2 flex items-center gap-3 hover:bg-[var(--color-bg-tertiary)] transition-colors"
                >
                  <span className="font-mono text-xs text-[var(--color-accent)]">{entry.name}</span>
                  <span className="text-[10px] font-mono text-[var(--color-text-muted)]">{entry.address_hex}</span>
                  {entry.ref_type && (
                    <span className="text-[10px] text-[var(--color-text-muted)]">{entry.ref_type}</span>
                  )}
                  {entry.is_import && (
                    <span className="text-[9px] px-1 rounded bg-[var(--color-purple)] text-white">IMP</span>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
