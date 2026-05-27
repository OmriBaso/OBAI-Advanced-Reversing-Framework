import { useEffect, useMemo, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { apiClient } from "../../api/client";
import { ArrowLeftRight, Loader, ChevronRight, ChevronDown, AlertTriangle } from "lucide-react";

type DiffStatus = "removed" | "added" | "size_diff" | "same_size" | "unchanged" | "changed";

interface DiffRow {
  name: string;
  status: DiffStatus;
  base_address: string | null;
  base_size: number | null;
  compare_address: string | null;
  compare_size: number | null;
}

interface FuncDiffOp {
  tag: "equal" | "replace" | "insert" | "delete";
  base_start: number;
  base_end: number;
  compare_start: number;
  compare_end: number;
}

interface FuncDiff {
  function: string;
  base_module: string;
  compare_module: string;
  base_insns: Array<{ address: string; mnemonic: string; op_str: string; normalized: string }>;
  compare_insns: Array<{ address: string; mnemonic: string; op_str: string; normalized: string }>;
  ops: FuncDiffOp[];
  identical: boolean;
}

const STATUS_META: Record<DiffStatus, { label: string; color: string; bg: string }> = {
  size_diff:  { label: "size diff",  color: "var(--color-red)",    bg: "rgba(248,81,73,0.08)" },
  changed:    { label: "changed",    color: "var(--color-red)",    bg: "rgba(248,81,73,0.12)" },
  added:      { label: "added",      color: "var(--color-accent)", bg: "rgba(88,166,255,0.08)" },
  removed:    { label: "removed",    color: "var(--color-text-muted)", bg: "rgba(110,118,129,0.10)" },
  same_size:  { label: "same size",  color: "var(--color-text-secondary)", bg: "transparent" },
  unchanged:  { label: "unchanged",  color: "var(--color-green)",  bg: "transparent" },
};

export function BinDiff() {
  const { sid, modules } = useAnalysisStore();
  const [baseModule, setBaseModule] = useState("");
  const [compareModule, setCompareModule] = useState("");
  const [summary, setSummary] = useState<DiffRow[] | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [selectedFunc, setSelectedFunc] = useState<string | null>(null);
  const [funcDiff, setFuncDiff] = useState<FuncDiff | null>(null);
  const [loadingFunc, setLoadingFunc] = useState(false);
  const [statusFilter, setStatusFilter] = useState<"all" | "diff_only">("diff_only");

  // Default the picks to the two most-recently added modules when modules load
  useEffect(() => {
    if (modules.length >= 2 && (!baseModule || !compareModule)) {
      const main = modules.find((m) => m.is_main) || modules[0];
      const other = modules.find((m) => m.name !== main.name);
      if (!baseModule) setBaseModule(main.name);
      if (!compareModule && other) setCompareModule(other.name);
    }
  }, [modules, baseModule, compareModule]);

  const runSummary = async () => {
    if (!sid || !baseModule || !compareModule || baseModule === compareModule) return;
    setLoadingSummary(true);
    setSummaryError(null);
    setSummary(null);
    setSelectedFunc(null);
    setFuncDiff(null);
    try {
      const r = await apiClient.getBinDiffSummary(sid, baseModule, compareModule);
      setSummary(r.diff);
    } catch (e) {
      setSummaryError(e instanceof Error ? e.message : "Diff failed");
    } finally {
      setLoadingSummary(false);
    }
  };

  const openFunc = async (name: string) => {
    setSelectedFunc(name);
    setFuncDiff(null);
    if (!sid) return;
    setLoadingFunc(true);
    try {
      const r = await apiClient.getBinDiffFunction(sid, baseModule, compareModule, name);
      setFuncDiff(r);
      // Reclassify same_size → unchanged/changed once we know the real answer
      if (summary) {
        setSummary((prev) =>
          prev
            ? prev.map((row) =>
                row.name === name && row.status === "same_size"
                  ? { ...row, status: r.identical ? "unchanged" : "changed" }
                  : row
              )
            : prev
        );
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingFunc(false);
    }
  };

  const counts = useMemo(() => {
    if (!summary) return null;
    const c: Record<string, number> = {};
    for (const r of summary) c[r.status] = (c[r.status] || 0) + 1;
    return c;
  }, [summary]);

  const visible = useMemo(() => {
    if (!summary) return [];
    if (statusFilter === "all") return summary;
    return summary.filter((r) => r.status !== "same_size" && r.status !== "unchanged");
  }, [summary, statusFilter]);

  if (modules.length < 2) {
    return (
      <div className="h-full flex items-center justify-center text-center px-8">
        <div className="max-w-sm space-y-2">
          <ArrowLeftRight className="mx-auto text-[var(--color-text-muted)]" size={28} />
          <p className="text-sm text-[var(--color-text-secondary)]">
            Bin Diff needs at least two modules loaded.
          </p>
          <p className="text-xs text-[var(--color-text-muted)]">
            Use <span className="text-[var(--color-text-primary)] font-medium">Add Binary</span> in
            the sidebar to load a second binary into this session.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
        <span className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
          Base
        </span>
        <select
          value={baseModule}
          onChange={(e) => setBaseModule(e.target.value)}
          className="px-2 py-1 text-[10px] rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          {modules.map((m) => (
            <option key={m.name} value={m.name}>
              {m.name}
            </option>
          ))}
        </select>
        <ArrowLeftRight size={12} className="text-[var(--color-text-muted)]" />
        <span className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
          Compare
        </span>
        <select
          value={compareModule}
          onChange={(e) => setCompareModule(e.target.value)}
          className="px-2 py-1 text-[10px] rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
        >
          {modules.map((m) => (
            <option key={m.name} value={m.name}>
              {m.name}
            </option>
          ))}
        </select>
        <button
          onClick={runSummary}
          disabled={!baseModule || !compareModule || baseModule === compareModule || loadingSummary}
          className="px-3 py-1 text-[10px] rounded bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          {loadingSummary ? "Diffing..." : "Run Diff"}
        </button>

        {counts && (
          <div className="flex items-center gap-2 ml-3 text-[10px] text-[var(--color-text-muted)]">
            <span style={{ color: STATUS_META.size_diff.color }}>{counts.size_diff || 0} size-diff</span>
            <span style={{ color: STATUS_META.added.color }}>{counts.added || 0} added</span>
            <span style={{ color: STATUS_META.removed.color }}>{counts.removed || 0} removed</span>
            <span style={{ color: STATUS_META.changed.color }}>{counts.changed || 0} changed</span>
            <span style={{ color: STATUS_META.unchanged.color }}>{counts.unchanged || 0} unchanged</span>
            <span>{counts.same_size || 0} same-size (click to verify)</span>
          </div>
        )}

        <div className="ml-auto flex items-center gap-1">
          <button
            onClick={() => setStatusFilter("diff_only")}
            className={`px-2 py-1 text-[10px] rounded transition-colors ${
              statusFilter === "diff_only"
                ? "bg-[var(--color-accent)] text-white"
                : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            Differences only
          </button>
          <button
            onClick={() => setStatusFilter("all")}
            className={`px-2 py-1 text-[10px] rounded transition-colors ${
              statusFilter === "all"
                ? "bg-[var(--color-accent)] text-white"
                : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            All
          </button>
        </div>
      </div>

      {summaryError && (
        <div className="px-3 py-2 text-[10px] text-[var(--color-red)] flex items-center gap-1.5">
          <AlertTriangle size={11} /> {summaryError}
        </div>
      )}

      {/* Split: function list + per-function diff */}
      <div className="flex-1 flex overflow-hidden">
        <div className="w-[320px] overflow-y-auto border-r border-[var(--color-border)] flex-shrink-0">
          {!summary && !loadingSummary && (
            <div className="p-4 text-xs text-[var(--color-text-muted)]">
              Pick two modules and click <span className="text-[var(--color-text-secondary)]">Run Diff</span>.
            </div>
          )}
          {loadingSummary && (
            <div className="p-4 flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
              <Loader size={12} className="animate-spin" /> Computing summary...
            </div>
          )}
          {visible.map((row) => {
            const meta = STATUS_META[row.status];
            const isSelected = row.name === selectedFunc;
            return (
              <button
                key={row.name}
                onClick={() => openFunc(row.name)}
                style={{ backgroundColor: isSelected ? "var(--color-bg-tertiary)" : meta.bg }}
                className="w-full text-left px-3 py-1.5 border-b border-[var(--color-border-light)] hover:bg-[var(--color-bg-tertiary)] transition-colors flex items-center gap-2"
              >
                <span
                  className="text-[9px] uppercase tracking-wide font-medium w-16 flex-shrink-0"
                  style={{ color: meta.color }}
                >
                  {meta.label}
                </span>
                <span className="font-mono text-xs text-[var(--color-text-primary)] truncate flex-1">
                  {row.name}
                </span>
                <span className="text-[9px] font-mono text-[var(--color-text-muted)] flex-shrink-0">
                  {row.base_size ?? "-"} → {row.compare_size ?? "-"}
                </span>
                {isSelected ? (
                  <ChevronDown size={11} className="text-[var(--color-text-muted)] flex-shrink-0" />
                ) : (
                  <ChevronRight size={11} className="text-[var(--color-text-muted)] flex-shrink-0" />
                )}
              </button>
            );
          })}
        </div>

        <div className="flex-1 overflow-hidden flex flex-col">
          {!selectedFunc && (
            <div className="h-full flex items-center justify-center text-xs text-[var(--color-text-muted)]">
              Select a function from the list to see the side-by-side disassembly diff.
            </div>
          )}
          {selectedFunc && loadingFunc && (
            <div className="h-full flex items-center justify-center text-xs text-[var(--color-text-muted)] gap-2">
              <Loader size={12} className="animate-spin" /> Diffing {selectedFunc}...
            </div>
          )}
          {funcDiff && <FunctionDiffView diff={funcDiff} />}
        </div>
      </div>
    </div>
  );
}

function FunctionDiffView({ diff }: { diff: FuncDiff }) {
  // Expand the ops list into per-line entries for both columns.
  // Each row: { base?: Insn, compare?: Insn, tag: equal|replace|insert|delete }
  const rows: Array<{
    base: FuncDiff["base_insns"][number] | null;
    compare: FuncDiff["compare_insns"][number] | null;
    tag: FuncDiffOp["tag"];
  }> = [];

  for (const op of diff.ops) {
    if (op.tag === "equal") {
      for (let i = 0; i < op.base_end - op.base_start; i++) {
        rows.push({
          base: diff.base_insns[op.base_start + i],
          compare: diff.compare_insns[op.compare_start + i],
          tag: "equal",
        });
      }
    } else if (op.tag === "replace") {
      const baseLen = op.base_end - op.base_start;
      const cmpLen = op.compare_end - op.compare_start;
      const maxLen = Math.max(baseLen, cmpLen);
      for (let i = 0; i < maxLen; i++) {
        rows.push({
          base: i < baseLen ? diff.base_insns[op.base_start + i] : null,
          compare: i < cmpLen ? diff.compare_insns[op.compare_start + i] : null,
          tag: "replace",
        });
      }
    } else if (op.tag === "delete") {
      for (let i = op.base_start; i < op.base_end; i++) {
        rows.push({ base: diff.base_insns[i], compare: null, tag: "delete" });
      }
    } else if (op.tag === "insert") {
      for (let i = op.compare_start; i < op.compare_end; i++) {
        rows.push({ base: null, compare: diff.compare_insns[i], tag: "insert" });
      }
    }
  }

  return (
    <div className="h-full flex flex-col">
      <div className="px-3 py-1.5 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)] flex items-center gap-3 text-[10px]">
        <span className="font-mono text-[var(--color-accent)]">{diff.function}</span>
        <span className="text-[var(--color-text-muted)]">{diff.base_module} ↔ {diff.compare_module}</span>
        {diff.identical ? (
          <span className="text-[var(--color-green)] font-medium">identical (normalized)</span>
        ) : (
          <span className="text-[var(--color-red)] font-medium">changed</span>
        )}
        <span className="ml-auto text-[var(--color-text-muted)]">
          {diff.base_insns.length} vs {diff.compare_insns.length} instructions
        </span>
      </div>

      <div className="flex-1 overflow-auto font-mono text-[11px]">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 bg-[var(--color-bg-secondary)] z-10">
            <tr className="text-left text-[var(--color-text-muted)]">
              <th className="px-3 py-1.5 border-b border-[var(--color-border)] w-1/2">{diff.base_module}</th>
              <th className="px-3 py-1.5 border-b border-[var(--color-border)] w-1/2">{diff.compare_module}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, idx) => {
              let leftBg = "";
              let rightBg = "";
              if (r.tag === "delete") leftBg = "rgba(248,81,73,0.18)";
              else if (r.tag === "insert") rightBg = "rgba(63,185,80,0.18)";
              else if (r.tag === "replace") {
                leftBg = "rgba(248,81,73,0.18)";
                rightBg = "rgba(63,185,80,0.18)";
              }
              const renderCell = (ins: typeof r.base, bg: string) => (
                <td className="px-3 py-0.5 align-top" style={{ backgroundColor: bg }}>
                  {ins ? (
                    <>
                      <span className="text-[var(--color-text-muted)] mr-2">{ins.address}</span>
                      <span className="text-[var(--color-text-primary)]">
                        {ins.mnemonic} {ins.op_str}
                      </span>
                    </>
                  ) : (
                    <span className="text-[var(--color-text-muted)]"> </span>
                  )}
                </td>
              );
              return (
                <tr key={idx}>
                  {renderCell(r.base, leftBg)}
                  {renderCell(r.compare, rightBg)}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
