import { useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { ModuleFilterBar } from "./ModuleFilterBar";

export function ExportsTable() {
  const { exports, modules, setSelectedFunction } = useAnalysisStore();
  const { setActiveTab } = useUIStore();
  const [moduleFilter, setModuleFilter] = useState("");

  const filtered = exports.filter((e) => !moduleFilter || e.module === moduleFilter);
  const hasMultipleModules = modules.length > 1;

  return (
    <div className="h-full flex flex-col">
      <ModuleFilterBar label="Exports for" value={moduleFilter} onChange={setModuleFilter} />
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-[var(--color-bg-secondary)]">
            <tr className="text-left text-[var(--color-text-muted)]">
              <th className="px-3 py-2">Function</th>
              {hasMultipleModules && <th className="px-3 py-2 w-32">Module</th>}
              <th className="px-3 py-2 w-28">Address</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((exp, i) => (
              <tr
                key={i}
                onClick={() => {
                  setSelectedFunction(exp.name, exp.module);
                  setActiveTab("pseudocode");
                }}
                className="border-t border-[var(--color-border-light)] hover:bg-[var(--color-bg-tertiary)] cursor-pointer"
                title="Click to view decompiled"
              >
                <td className="px-3 py-1.5 font-mono text-[var(--color-text-primary)]">{exp.name}</td>
                {hasMultipleModules && (
                  <td className="px-3 py-1.5 font-mono text-[var(--color-text-muted)]">{exp.module || "-"}</td>
                )}
                <td className="px-3 py-1.5 font-mono text-[var(--color-text-muted)]">{exp.address_hex}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
