import { useState, useEffect } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { Settings, Database, Download, Monitor, LogOut } from "lucide-react";

export function Header() {
  const { sid, filename, arch, symbolsLoaded, functions } = useAnalysisStore();
  const { openModal } = useUIStore();
  const [agentCount, setAgentCount] = useState(0);

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await apiClient.getRemoteAgents();
        setAgentCount(data.agents.filter((a) => a.alive).length);
      } catch {
        setAgentCount(0);
      }
    };
    poll();
    const interval = setInterval(poll, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-12 flex items-center justify-between px-4 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[var(--color-accent)]" />
          <span className="font-semibold text-sm tracking-wide">OBAI</span>
        </div>

        {sid && (
          <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)] ml-4">
            <span className="px-2 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] font-medium">
              {filename}
            </span>
            <span>{arch}</span>
            <span>{functions.length} functions</span>
            {symbolsLoaded && (
              <span className="text-[var(--color-green)]">symbols loaded</span>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-1">
        <button
          onClick={() => openModal("agents")}
          className="relative flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          <Monitor size={14} />
          Agents
          {agentCount > 0 && (
            <span className="flex items-center justify-center min-w-[16px] h-4 px-1 rounded-full bg-[var(--color-green)] text-white text-[10px] font-bold">
              {agentCount}
            </span>
          )}
        </button>
        {sid && (
          <button
            onClick={() => openModal("exportSelect")}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
          >
            <Download size={14} /> Export .c
          </button>
        )}
        {sid && (
          <button
            onClick={() => openModal("exitSession")}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-[var(--color-red)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
            title="End the current reversing session in this browser (DB stays saved on disk)"
          >
            <LogOut size={14} /> Exit Reversing Session
          </button>
        )}
        <button
          onClick={() => openModal("databases")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          <Database size={14} /> Databases
        </button>
        <button
          onClick={() => openModal("config")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          <Settings size={14} /> Settings
        </button>
      </div>
    </header>
  );
}
