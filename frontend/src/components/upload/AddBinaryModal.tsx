import { useRef, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { X, Upload, Loader, FilePlus } from "lucide-react";

type Mode = "basic" | "basic_pdb" | "full_map";

const MODES: Array<{ value: Mode; label: string; hint: string }> = [
  { value: "basic", label: "Basic Analysis", hint: "Just this binary. Fastest." },
  {
    value: "basic_pdb",
    label: "Basic + External PDBs",
    hint: "Same as Basic for added binaries today — full dependency picker is coming.",
  },
  {
    value: "full_map",
    label: "Full Map Analysis",
    hint: "Same as Basic for added binaries today — full dependency picker is coming.",
  },
];

export function AddBinaryModal() {
  const { sid, loadAllData } = useAnalysisStore();
  const { closeModal } = useUIStore();
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<Mode>("basic");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = async () => {
    if (!file || !sid) return;
    setLoading(true);
    setError(null);
    try {
      await apiClient.addBinary(sid, file, mode);
      await loadAllData(sid);
      closeModal();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Add binary failed");
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={loading ? undefined : closeModal}
    >
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[460px] shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <FilePlus size={14} /> Add Binary to Session
          </h3>
          <button
            onClick={closeModal}
            disabled={loading}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] disabled:opacity-30"
          >
            <X size={16} />
          </button>
        </div>

        <div className="p-4 space-y-3">
          <p className="text-xs text-[var(--color-text-secondary)] leading-tight">
            Adds another binary as a new module in this reversing session. Useful for
            comparing two versions (see <span className="text-[var(--color-text-primary)] font-medium">Bin Diff</span>),
            or for looking at a related library alongside the main binary.
          </p>

          <div>
            <label className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
              Binary
            </label>
            <button
              onClick={() => inputRef.current?.click()}
              disabled={loading}
              className="w-full mt-1 flex items-center gap-2 px-3 py-2 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] hover:border-[var(--color-text-muted)] disabled:opacity-50 transition-colors"
            >
              <Upload size={12} />
              {file ? file.name : "Choose a file..."}
            </button>
            <input
              ref={inputRef}
              type="file"
              accept=".dll,.exe,.sys,.drv,.bin,.elf,.so"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
          </div>

          <div>
            <label className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
              Analysis Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as Mode)}
              disabled={loading}
              className="w-full mt-1 px-2 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] disabled:opacity-50"
            >
              {MODES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
            <p className="text-[10px] text-[var(--color-text-muted)] leading-tight mt-1">
              {MODES.find((m) => m.value === mode)?.hint}
            </p>
          </div>

          {error && (
            <div className="text-[10px] text-[var(--color-red)] leading-tight">
              {error}
            </div>
          )}

          <div className="flex gap-2 justify-end pt-1">
            <button
              onClick={closeModal}
              disabled={loading}
              className="px-3 py-1.5 text-xs rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={submit}
              disabled={!file || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              {loading ? <Loader size={12} className="animate-spin" /> : <FilePlus size={12} />}
              {loading ? "Analyzing..." : "Add Binary"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
