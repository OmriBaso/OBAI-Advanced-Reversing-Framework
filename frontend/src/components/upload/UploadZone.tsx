import { useState, useRef, useCallback } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { Upload, Loader } from "lucide-react";

type AnalysisMode = "basic" | "basic_pdb" | "full_map";

const MODE_OPTIONS: Array<{ value: AnalysisMode; label: string; hint: string }> = [
  {
    value: "basic",
    label: "Basic Analysis",
    hint: "Main binary only. Fastest.",
  },
  {
    value: "basic_pdb",
    label: "Basic + External PDBs",
    hint: "Pull DLLs from path for symbol-name resolution and PDB download. No per-DLL decompilation.",
  },
  {
    value: "full_map",
    label: "Full Map Analysis",
    hint: "Run Ghidra on every linked DLL too. Cross-module decompile + nav. Slowest.",
  },
];

export function UploadZone() {
  const { runAnalysis } = useAnalysisStore();
  const { openModal, setDependencyInfo, setRichDependencyInfo } = useUIStore();
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [mode, setMode] = useState<AnalysisMode>("basic");
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    async (file: File) => {
      setLoading(true);
      setStatus("Uploading...");
      try {
        const result = await apiClient.upload(file, mode);

        if ((result.mode === "basic_pdb" || result.mode === "full_map") && result.imports && result.imports.length > 0) {
          setRichDependencyInfo(result.analysis_id, result.mode, result.imports);
          setStatus("");
          setLoading(false);
          openModal("dependencies");
          return;
        }

        if (result.missing_dlls && result.missing_dlls.length > 0) {
          setDependencyInfo(result.analysis_id, result.missing_dlls);
          setStatus("");
          setLoading(false);
          openModal("dependencies");
          return;
        }

        setStatus("");
        setLoading(false);
        runAnalysis(result.analysis_id);
      } catch (e: unknown) {
        setStatus(`Error: ${e instanceof Error ? e.message : "Upload failed"}`);
        setLoading(false);
      }
    },
    [mode, runAnalysis, openModal, setDependencyInfo, setRichDependencyInfo]
  );

  const currentHint = MODE_OPTIONS.find((m) => m.value === mode)?.hint ?? "";

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  return (
    <div className="flex flex-col gap-3 items-stretch" style={{ width: 448 }}>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
          dragging
            ? "border-[var(--color-accent)] bg-[var(--color-bg-tertiary)]"
            : "border-[var(--color-border)] hover:border-[var(--color-text-muted)]"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".dll,.exe,.sys,.drv,.bin,.elf,.so"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />

        {loading ? (
          <div className="flex flex-col items-center gap-3">
            <Loader size={32} className="text-[var(--color-accent)] animate-spin" />
            <span className="text-sm text-[var(--color-text-secondary)]">{status}</span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <Upload size={32} className="text-[var(--color-text-muted)]" />
            <div>
              <p className="text-sm text-[var(--color-text-secondary)]">
                Drop a binary here or click to browse
              </p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                .dll, .exe, .sys, .drv, .bin, .elf, .so
              </p>
            </div>
            {status && (
              <p className="text-xs text-[var(--color-red)]">{status}</p>
            )}
          </div>
        )}
      </div>

      <div
        className="flex flex-col gap-1 px-3 py-2 rounded border border-[var(--color-border)] bg-[var(--color-bg-secondary)]"
        onClick={(e) => e.stopPropagation()}
        style={{ height: 108 }}
      >
        <label className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
          Analysis mode
        </label>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as AnalysisMode)}
          className="px-2 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          {MODE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <div className="text-[10px] text-[var(--color-text-muted)] leading-tight overflow-hidden flex-1">
          {currentHint}
        </div>
      </div>
    </div>
  );
}
