import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { AlertTriangle, X } from "lucide-react";

export function ExitSessionModal() {
  const { reset } = useAnalysisStore();
  const { closeModal } = useUIStore();

  const onConfirm = () => {
    reset();
    closeModal();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={closeModal}
    >
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[440px] shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold flex items-center gap-2 text-[var(--color-red)]">
            <AlertTriangle size={14} /> Exit Reversing Session
          </h3>
          <button
            onClick={closeModal}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
          >
            <X size={16} />
          </button>
        </div>

        <div className="p-5 space-y-2">
          <p className="text-sm text-[var(--color-text-primary)]">
            Are you sure? This action is irreversible.
          </p>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Your analysis database is saved on disk and can be reloaded later from
            <span className="text-[var(--color-text-primary)] font-medium"> Databases</span>.
            This only ends the current browser session — chats, pseudocode caches, and Ghidra projects all stay.
          </p>
        </div>

        <div className="flex gap-2 justify-end px-4 py-3 border-t border-[var(--color-border)]">
          <button
            onClick={closeModal}
            className="px-3 py-1.5 text-xs rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            No, cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-3 py-1.5 text-xs rounded bg-[var(--color-red)] text-white hover:opacity-90 transition-opacity"
          >
            Yes, I am sure
          </button>
        </div>
      </div>
    </div>
  );
}
