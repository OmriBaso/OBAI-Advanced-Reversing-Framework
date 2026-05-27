import { useMemo, useState } from "react";
import { useUIStore } from "../../stores/uiStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { apiClient } from "../../api/client";
import { X, Upload, SkipForward, Check, FolderSearch, Layers } from "lucide-react";

export function DependencyModal() {
  const {
    closeModal,
    pendingSid,
    pendingMode,
    missingDlls,
    pendingImports,
    uploadedDlls,
    filledFromPath,
    markDllUploaded,
    markDllsFilledFromPath,
    clearDependencyInfo,
  } = useUIStore();
  const { runAnalysis } = useAnalysisStore();
  const [status, setStatus] = useState("");
  const [filling, setFilling] = useState(false);

  const isFullMap = pendingMode === "full_map";
  const isRich = pendingMode === "full_map" || pendingMode === "basic_pdb";

  const fillable = useMemo(
    () =>
      pendingImports.filter(
        (i) => i.found_at && !filledFromPath.has(i.name) && !uploadedDlls.has(i.name)
      ),
    [pendingImports, filledFromPath, uploadedDlls]
  );

  const handleContinue = () => {
    if (!pendingSid) return;
    const sid = pendingSid;
    clearDependencyInfo();
    closeModal();
    runAnalysis(sid);
  };

  const handleUploadDll = async (dll: string, file: File) => {
    try {
      await apiClient.uploadLibrary(pendingSid, file, dll);
      markDllUploaded(dll);
      setStatus("");
    } catch (e: unknown) {
      setStatus(`Failed to upload ${dll}: ${e instanceof Error ? e.message : "error"}`);
    }
  };

  const handleFillFromPath = async () => {
    if (!pendingSid || fillable.length === 0) return;
    setFilling(true);
    try {
      const result = await apiClient.fillFromPath(
        pendingSid,
        fillable.map((f) => ({ name: f.name, found_at: f.found_at! }))
      );
      markDllsFilledFromPath(result.copied.map((c) => c.name));
      if (result.errors.length > 0) {
        setStatus(`${result.errors.length} DLL(s) failed to copy from path.`);
      } else {
        setStatus("");
      }
    } catch (e: unknown) {
      setStatus(`Fill from path failed: ${e instanceof Error ? e.message : "error"}`);
    } finally {
      setFilling(false);
    }
  };

  const renderStandard = () => (
    <>
      <p className="text-xs text-[var(--color-text-secondary)] mb-3">
        The following DLLs were not found on the system or in known paths. Upload
        them for better analysis or skip to continue without them.
      </p>

      {missingDlls.length === 0 ? (
        <p className="text-xs text-[var(--color-text-muted)] mb-4 italic">
          No missing dependencies detected.
        </p>
      ) : (
        <div className="space-y-2 mb-4 max-h-72 overflow-y-auto">
          {missingDlls.map((dll) => {
            const uploaded = uploadedDlls.has(dll);
            return (
              <div
                key={dll}
                className="flex items-center justify-between px-3 py-2 rounded bg-[var(--color-bg-tertiary)]"
              >
                <span
                  className={`text-xs font-mono ${
                    uploaded ? "text-[var(--color-green)]" : "text-[var(--color-text-primary)]"
                  }`}
                >
                  {dll}
                </span>
                {uploaded ? (
                  <span className="flex items-center gap-1 px-2 py-1 text-[10px] text-[var(--color-green)]">
                    <Check size={10} /> Uploaded
                  </span>
                ) : (
                  <label className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-hover)] text-[var(--color-accent)] cursor-pointer hover:opacity-80">
                    <Upload size={10} /> Upload
                    <input
                      type="file"
                      className="hidden"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (file) await handleUploadDll(dll, file);
                      }}
                    />
                  </label>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );

  const renderRich = () => {
    const filledCount = pendingImports.filter(
      (i) => filledFromPath.has(i.name) || uploadedDlls.has(i.name)
    ).length;
    const foundOnSystem = pendingImports.filter((i) => i.found_at).length;
    const notFound = pendingImports.filter((i) => !i.found_at);

    return (
      <>
        <div className="flex items-center justify-between mb-3">
          <p className="text-xs text-[var(--color-text-secondary)] leading-tight">
            {isFullMap
              ? "Full Map Analysis will run Ghidra on every linked DLL. Bulk-fill DLLs found on this machine, then upload custom versions for any others."
              : "Basic + External PDBs links each loaded DLL (so Ghidra resolves their symbols and downloads PDBs) but does NOT decompile them. Faster than Full Map."}
          </p>
        </div>

        <div className="flex items-center justify-between mb-3 px-3 py-2 rounded bg-[var(--color-bg-tertiary)] text-[10px]">
          <span className="text-[var(--color-text-muted)]">
            {pendingImports.length} imported · {foundOnSystem} found on path · {filledCount} loaded
            {notFound.length > 0 && ` · ${notFound.length} not found`}
          </span>
          <button
            onClick={handleFillFromPath}
            disabled={filling || fillable.length === 0}
            className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-40 transition-opacity"
            title="Copy every DLL found on this system into the analysis"
          >
            <FolderSearch size={10} /> Fill from Path ({fillable.length})
          </button>
        </div>

        <div className="space-y-1 mb-4 max-h-80 overflow-y-auto">
          {pendingImports.map((imp) => {
            const uploaded = uploadedDlls.has(imp.name);
            const filled = filledFromPath.has(imp.name);
            const loaded = uploaded || filled;
            return (
              <div
                key={imp.name}
                className="flex items-center justify-between px-3 py-1.5 rounded bg-[var(--color-bg-tertiary)] gap-2"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-mono truncate ${
                        loaded ? "text-[var(--color-green)]" : "text-[var(--color-text-primary)]"
                      }`}
                      title={imp.name}
                    >
                      {imp.name}
                    </span>
                    {imp.is_system && (
                      <span className="text-[9px] px-1 rounded bg-[var(--color-bg-primary)] text-[var(--color-text-muted)] flex-shrink-0">
                        system
                      </span>
                    )}
                  </div>
                  <div className="text-[9px] text-[var(--color-text-muted)] truncate" title={imp.found_at ?? "not found"}>
                    {imp.found_at ?? "not found on this system"}
                  </div>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {filled && !uploaded && (
                    <span className="flex items-center gap-1 px-2 py-1 text-[10px] text-[var(--color-green)]">
                      <Check size={10} /> path
                    </span>
                  )}
                  {uploaded && (
                    <span className="flex items-center gap-1 px-2 py-1 text-[10px] text-[var(--color-green)]">
                      <Check size={10} /> uploaded
                    </span>
                  )}
                  <label className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-hover)] text-[var(--color-accent)] cursor-pointer hover:opacity-80">
                    <Upload size={10} /> {loaded ? "Override" : "Upload"}
                    <input
                      type="file"
                      className="hidden"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (file) await handleUploadDll(imp.name, file);
                      }}
                    />
                  </label>
                </div>
              </div>
            );
          })}
        </div>
      </>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeModal}>
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[520px] shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            {isRich && <Layers size={14} />}
            {isFullMap
              ? "Full Map Dependencies"
              : isRich
              ? "Basic + External PDB Dependencies"
              : "Missing Dependencies"}
          </h3>
          <button onClick={closeModal} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]">
            <X size={16} />
          </button>
        </div>

        <div className="p-4">
          {isRich ? renderRich() : renderStandard()}

          {status && <p className="text-xs text-[var(--color-red)] mb-2">{status}</p>}

          <div className="flex gap-2 justify-end">
            <button
              onClick={handleContinue}
              className="flex items-center gap-1.5 px-4 py-2 rounded text-xs bg-[var(--color-accent)] text-white hover:opacity-90 transition-opacity"
            >
              <SkipForward size={12} /> Continue Analysis
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
