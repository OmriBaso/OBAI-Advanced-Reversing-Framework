import { useAnalysisStore } from "../../stores/analysisStore";
import { Layers } from "lucide-react";

interface Props {
  label: string;
  value: string;
  onChange: (value: string) => void;
}

/**
 * Per-tab module filter dropdown. Each tab keeps its own filter so you can have
 * "Strings for hman.dll" while the Imports tab is showing kernel32.dll.
 * Only renders when more than one module is loaded.
 */
export function ModuleFilterBar({ label, value, onChange }: Props) {
  const { modules } = useAnalysisStore();
  if (modules.length <= 1) return null;

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
      <Layers size={11} className="text-[var(--color-text-muted)] flex-shrink-0" />
      <span className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-2 py-0.5 text-[10px] rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
      >
        <option value="">All modules ({modules.length})</option>
        {modules.map((m) => (
          <option key={m.name} value={m.name}>
            {m.name}
            {m.is_main ? " (main)" : ""}
          </option>
        ))}
      </select>
    </div>
  );
}
