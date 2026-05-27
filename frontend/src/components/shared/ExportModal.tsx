import { useState, useMemo, useDeferredValue } from "react";
import { useUIStore } from "../../stores/uiStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { X, Download, Search, CheckSquare, Square, Loader, ChevronsDown } from "lucide-react";

const PAGE_SIZE = 100;

export function ExportModal() {
  const { closeModal } = useUIStore();
  const { sid, functions } = useAnalysisStore();

  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [exporting, setExporting] = useState(false);
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  const nonImportFunctions = useMemo(
    () => functions.filter((f) => !f.is_import),
    [functions]
  );

  const filtered = useMemo(() => {
    if (!deferredSearch.trim()) return nonImportFunctions;
    const q = deferredSearch.toLowerCase();
    return nonImportFunctions.filter((f) => f.name.toLowerCase().includes(q));
  }, [nonImportFunctions, deferredSearch]);

  const visible = useMemo(
    () => filtered.slice(0, visibleCount),
    [filtered, visibleCount]
  );

  const allFilteredSelected = filtered.length > 0 && filtered.every((f) => selected.has(f.name));

  const toggleOne = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const toggleAll = () => {
    if (allFilteredSelected) {
      setSelected((prev) => {
        const next = new Set(prev);
        for (const f of filtered) next.delete(f.name);
        return next;
      });
    } else {
      setSelected((prev) => {
        const next = new Set(prev);
        for (const f of filtered) next.add(f.name);
        return next;
      });
    }
  };

  const handleExport = async () => {
    if (selected.size === 0) return;
    setExporting(true);
    try {
      const resp = await fetch(`/api/analysis/${sid}/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ functions: Array.from(selected) }),
      });
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
      closeModal();
    } catch (e) {
      console.error("Export failed:", e);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeModal}>
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[500px] max-h-[70vh] flex flex-col shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Download size={14} /> Export to .c
          </h3>
          <button onClick={closeModal} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]">
            <X size={16} />
          </button>
        </div>

        <div className="px-4 pt-3 pb-2 space-y-2 border-b border-[var(--color-border)]">
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
            <input
              type="text"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setVisibleCount(PAGE_SIZE); }}
              placeholder="Search functions..."
              className="w-full pl-7 pr-3 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)]"
              autoFocus
            />
          </div>

          <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)]">
            <button
              onClick={toggleAll}
              className="flex items-center gap-1.5 hover:text-[var(--color-text-primary)] transition-colors"
            >
              {allFilteredSelected ? <CheckSquare size={12} /> : <Square size={12} />}
              {allFilteredSelected ? "Deselect all" : "Select all"} ({filtered.length})
            </button>
            <span>{selected.size} selected</span>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto min-h-0">
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-xs text-[var(--color-text-muted)]">
              No functions match your search.
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-light)]">
              {visible.map((f) => (
                <button
                  key={f.name}
                  onClick={() => toggleOne(f.name)}
                  className="w-full text-left px-4 py-1.5 flex items-center gap-2.5 hover:bg-[var(--color-bg-tertiary)] transition-colors"
                >
                  {selected.has(f.name) ? (
                    <CheckSquare size={13} className="text-[var(--color-accent)] flex-shrink-0" />
                  ) : (
                    <Square size={13} className="text-[var(--color-text-muted)] flex-shrink-0" />
                  )}
                  <span className="text-xs text-[var(--color-text-primary)] font-mono truncate">
                    {f.name}
                  </span>
                  <span className="ml-auto text-[10px] text-[var(--color-text-muted)] font-mono flex-shrink-0">
                    {f.address_hex}
                  </span>
                </button>
              ))}
              {visibleCount < filtered.length && (
                <button
                  onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
                  className="w-full py-2 flex items-center justify-center gap-1.5 text-[10px] text-[var(--color-accent)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
                >
                  <ChevronsDown size={12} />
                  Show more ({filtered.length - visibleCount} remaining)
                </button>
              )}
            </div>
          )}
        </div>

        <div className="px-4 py-3 border-t border-[var(--color-border)]">
          <button
            onClick={handleExport}
            disabled={selected.size === 0 || exporting}
            className="w-full flex items-center justify-center gap-2 py-2 rounded text-xs bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity"
          >
            {exporting ? (
              <><Loader size={12} className="animate-spin" /> Exporting...</>
            ) : (
              <><Download size={12} /> Export {selected.size} function{selected.size !== 1 ? "s" : ""}</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
