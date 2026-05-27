import { useEffect, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { apiClient } from "../../api/client";
import type { DisasmInstruction } from "../../api/types";

export function DisassemblyView() {
  const { sid, selectedFunction, selectedFunctionModule } = useAnalysisStore();
  const [instructions, setInstructions] = useState<DisasmInstruction[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!sid || !selectedFunction) {
      setInstructions([]);
      return;
    }
    setLoading(true);
    apiClient
      .getDisasm(sid, selectedFunction, selectedFunctionModule || undefined)
      .then((r) => setInstructions(r.instructions as unknown as DisasmInstruction[]))
      .catch(() => setInstructions([]))
      .finally(() => setLoading(false));
  }, [sid, selectedFunction, selectedFunctionModule]);

  if (!selectedFunction) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-[var(--color-text-muted)]">
        Select a function to view disassembly
      </div>
    );
  }

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <div className="w-4 h-4 border-2 border-[var(--color-accent)] border-t-transparent rounded-full animate-spin" />
          Disassembling...
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <table className="w-full text-xs font-mono">
        <thead className="sticky top-0 bg-[var(--color-bg-secondary)]">
          <tr className="text-left text-[var(--color-text-muted)]">
            <th className="px-3 py-2 w-28">Address</th>
            <th className="px-3 py-2 w-28">Bytes</th>
            <th className="px-3 py-2 w-20">Mnemonic</th>
            <th className="px-3 py-2">Operands</th>
            <th className="px-3 py-2 w-40">Label</th>
          </tr>
        </thead>
        <tbody>
          {instructions.map((insn, i) => (
            <tr
              key={i}
              className={`border-t border-[var(--color-border-light)] hover:bg-[var(--color-bg-tertiary)] ${
                insn.type === "call"
                  ? "text-[var(--color-accent)]"
                  : insn.type === "jump"
                  ? "text-[var(--color-orange)]"
                  : insn.type === "ret"
                  ? "text-[var(--color-red)]"
                  : "text-[var(--color-text-primary)]"
              }`}
            >
              <td className="px-3 py-1 text-[var(--color-text-muted)]">{insn.address}</td>
              <td className="px-3 py-1 text-[var(--color-text-muted)]">{insn.bytes}</td>
              <td className="px-3 py-1 font-semibold">{insn.mnemonic}</td>
              <td className="px-3 py-1">{insn.op_str}</td>
              <td className="px-3 py-1 text-[var(--color-purple)]">{insn.label}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
