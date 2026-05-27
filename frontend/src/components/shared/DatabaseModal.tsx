import { useState, useEffect } from "react";
import { useUIStore } from "../../stores/uiStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { apiClient } from "../../api/client";
import { X, Database, Loader } from "lucide-react";

interface DbEntry {
  filename: string;
  binary_name: string;
  arch: string;
  symbols_loaded: boolean;
  n_functions: number;
  n_vulnerabilities: number;
  created_at: string;
}

export function DatabaseModal() {
  const { closeModal } = useUIStore();
  const { setSid, setAnalysisInfo, loadAllData } = useAnalysisStore();
  const [databases, setDatabases] = useState<DbEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingId, setLoadingId] = useState<string | null>(null);

  useEffect(() => {
    apiClient
      .listDatabases()
      .then((dbs) => {
        dbs.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
        setDatabases(dbs);
      })
      .finally(() => setLoading(false));
  }, []);

  const handleLoad = async (db: DbEntry) => {
    setLoadingId(db.filename);
    try {
      const result = await apiClient.loadDatabase(db.filename);
      setSid(result.analysis_id);
      setAnalysisInfo({
        filename: result.filename,
        arch: result.arch,
        symbols_loaded: result.symbols_loaded,
      });
      await loadAllData(result.analysis_id);
      closeModal();
    } catch (e) {
      console.error("Failed to load database:", e);
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeModal}>
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[550px] max-h-[70vh] flex flex-col shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Database size={14} /> Saved Analyses
          </h3>
          <button onClick={closeModal} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8 text-sm text-[var(--color-text-secondary)]">
              <Loader size={16} className="animate-spin mr-2" /> Loading...
            </div>
          ) : databases.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-sm text-[var(--color-text-muted)]">
              No saved analyses found.
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-light)]">
              {databases.map((db) => (
                <button
                  key={db.filename}
                  onClick={() => handleLoad(db)}
                  disabled={loadingId !== null}
                  className="w-full text-left px-4 py-3 hover:bg-[var(--color-bg-tertiary)] transition-colors disabled:opacity-50"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-xs font-medium text-[var(--color-text-primary)]">
                        {db.binary_name}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[10px] text-[var(--color-text-muted)]">
                        <span>{db.arch}</span>
                        <span>{db.n_functions} functions</span>
                        {db.n_vulnerabilities > 0 && (
                          <span className="text-[var(--color-red)]">{db.n_vulnerabilities} vulns</span>
                        )}
                        {db.symbols_loaded && (
                          <span className="text-[var(--color-green)]">symbols</span>
                        )}
                        <span>{db.created_at}</span>
                      </div>
                    </div>
                    {loadingId === db.filename && (
                      <Loader size={14} className="animate-spin text-[var(--color-accent)]" />
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
