import { useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { Search, Loader, AlertCircle } from "lucide-react";

interface GrepMatch {
  module: string;
  function: string;
  address_hex: string;
  lines: Array<{ line_no: number; text: string; is_match: boolean }>;
}

interface GrepResult {
  matches: GrepMatch[];
  scanned: number;
  total_in_scope: number;
  decompiled: number;
  budget_exhausted: boolean;
  early_stop: boolean;
  pattern: string;
}

export function CodeSearch() {
  const { sid, modules, setSelectedFunction } = useAnalysisStore();
  const { setActiveTab } = useUIStore();
  const [pattern, setPattern] = useState("");
  const [module, setModule] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [budget, setBudget] = useState(1000);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GrepResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    const p = pattern.trim();
    if (!p || !sid) return;
    setLoading(true);
    setError(null);
    try {
      const r = await apiClient.grepFunctions(sid, p, {
        module: module || undefined,
        case_sensitive: caseSensitive,
        max_decompile_budget: budget,
      });
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Search failed");
    } finally {
      setLoading(false);
    }
  };

  const jump = (m: GrepMatch) => {
    setSelectedFunction(m.function, m.module);
    setActiveTab("pseudocode");
  };

  const hasMultipleModules = modules.length > 1;

  return (
    <div className="h-full flex flex-col">
      <div className="p-3 border-b border-[var(--color-border)] space-y-2">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-2.5 top-2 text-[var(--color-text-muted)]" />
            <input
              type="text"
              placeholder='Regex over function bodies (e.g. memcmp\s*\(.*[Pp]assw)'
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") run();
              }}
              className="w-full pl-8 pr-3 py-1.5 text-xs font-mono rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)]"
            />
          </div>
          <button
            onClick={run}
            disabled={!pattern.trim() || loading}
            className="px-4 py-1.5 text-xs rounded bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-40 transition-opacity flex items-center gap-1.5"
          >
            {loading ? <Loader size={12} className="animate-spin" /> : <Search size={12} />}
            {loading ? "Searching..." : "Grep"}
          </button>
        </div>

        <div className="flex items-center gap-3 text-[10px]">
          {hasMultipleModules && (
            <label className="flex items-center gap-1.5">
              <span className="text-[var(--color-text-muted)]">module</span>
              <select
                value={module}
                onChange={(e) => setModule(e.target.value)}
                className="px-2 py-0.5 text-[10px] rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
              >
                <option value="">all</option>
                {modules.map((m) => (
                  <option key={m.name} value={m.name}>
                    {m.name}
                  </option>
                ))}
              </select>
            </label>
          )}

          <label className="flex items-center gap-1 cursor-pointer text-[var(--color-text-muted)]">
            <input
              type="checkbox"
              checked={caseSensitive}
              onChange={(e) => setCaseSensitive(e.target.checked)}
              className="cursor-pointer"
            />
            case-sensitive
          </label>

          <label className="flex items-center gap-1.5 text-[var(--color-text-muted)]" title="Max NEW functions to decompile this call. Cache hits are free.">
            decompile budget
            <input
              type="number"
              min={0}
              max={10000}
              step={500}
              value={budget}
              onChange={(e) => setBudget(Math.max(0, Math.min(10000, parseInt(e.target.value) || 0)))}
              className="w-16 px-1 py-0.5 text-[10px] rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
            />
          </label>
        </div>

        {error && (
          <div className="flex items-center gap-1.5 text-[10px] text-[var(--color-red)]">
            <AlertCircle size={11} /> {error}
          </div>
        )}

        {result && !error && (
          <div className="text-[10px] text-[var(--color-text-muted)]">
            {result.matches.length} matching function{result.matches.length === 1 ? "" : "s"}
            {" · "}
            {result.scanned}/{result.total_in_scope} scanned
            {result.decompiled > 0 && ` · ${result.decompiled} newly decompiled`}
            {result.budget_exhausted && (
              <span className="text-[var(--color-orange)]"> · budget exhausted, raise it for more</span>
            )}
            {result.early_stop && (
              <span className="text-[var(--color-orange)]"> · stopped at max_results</span>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {!result && !loading && (
          <div className="h-full flex items-center justify-center text-xs text-[var(--color-text-muted)] px-6 text-center">
            Regex-search inside every function's decompiled pseudocode. First search on a
            sparsely-cached binary triggers on-demand decompilation; later searches are fast.
          </div>
        )}

        {result && result.matches.length === 0 && !loading && (
          <div className="h-full flex items-center justify-center text-xs text-[var(--color-text-muted)]">
            No matches.
          </div>
        )}

        {result && result.matches.map((m, i) => (
          <div
            key={i}
            className="border-b border-[var(--color-border-light)] hover:bg-[var(--color-bg-tertiary)] cursor-pointer transition-colors"
            onClick={() => jump(m)}
            title="Click to open in decompile tab"
          >
            <div className="px-4 py-1.5 flex items-center gap-3">
              <span className="text-xs font-mono text-[var(--color-accent)] truncate">
                {m.function}
              </span>
              {modules.length > 1 && (
                <span className="text-[9px] px-1 rounded bg-[var(--color-bg-primary)] text-[var(--color-text-muted)] font-mono flex-shrink-0">
                  {m.module}
                </span>
              )}
              <span className="text-[10px] text-[var(--color-text-muted)] font-mono flex-shrink-0">
                {m.address_hex}
              </span>
            </div>
            <div className="px-4 pb-2 pl-8 space-y-0.5">
              {m.lines.map((ln, j) => (
                <div
                  key={j}
                  className={`text-[11px] font-mono leading-tight ${
                    ln.is_match
                      ? "text-[var(--color-text-primary)]"
                      : "text-[var(--color-text-muted)]"
                  }`}
                >
                  <span className="text-[var(--color-text-muted)] mr-2">{ln.line_no}:</span>
                  {ln.text}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
