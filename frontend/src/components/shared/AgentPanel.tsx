import { useState, useEffect, useCallback } from "react";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { X, Monitor, Shield, ShieldOff, RefreshCw, Trash2, Wifi, WifiOff } from "lucide-react";

interface RemoteAgent {
  agent_id: string;
  hostname: string;
  domain: string;
  username: string;
  os_version: string;
  ip_addresses: string[];
  is_elevated: boolean;
  alive: boolean;
  connected_seconds: number;
}

export function AgentPanel() {
  const { closeModal } = useUIStore();
  const [agents, setAgents] = useState<RemoteAgent[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiClient.getRemoteAgents();
      setAgents(data.agents);
    } catch {
      setAgents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10000);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleDisconnect = async (agentId: string) => {
    try {
      await apiClient.disconnectAgent(agentId);
      setAgents((prev) => prev.filter((a) => a.agent_id !== agentId));
    } catch { /* ignore */ }
  };

  const formatUptime = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeModal}>
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[560px] max-h-[70vh] shadow-xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-2">
            <Monitor size={16} className="text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold">Remote Agents</h3>
            <span className="text-xs text-[var(--color-text-muted)]">
              ({agents.filter((a) => a.alive).length} connected)
            </span>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={refresh}
              className="p-1.5 rounded text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)]"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            </button>
            <button
              onClick={closeModal}
              className="p-1.5 rounded text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
            >
              <X size={14} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {agents.length === 0 ? (
            <div className="text-center py-8">
              <WifiOff size={32} className="mx-auto mb-3 text-[var(--color-text-muted)]" />
              <p className="text-sm text-[var(--color-text-secondary)]">No remote agents connected</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                Run <code className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] font-mono text-[10px]">OBAIAgent.exe &lt;backend-ip&gt;:8080</code> on a target machine
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {agents.map((agent) => (
                <div
                  key={agent.agent_id}
                  className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] p-3"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${agent.alive ? "bg-[var(--color-green)]" : "bg-[var(--color-red)]"}`} />
                      <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                        {agent.hostname}
                      </span>
                      <span className="text-xs font-mono text-[var(--color-text-muted)]">
                        {agent.agent_id}
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      {agent.is_elevated ? (
                        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-[var(--color-red)]/10 text-[var(--color-red)]">
                          <Shield size={10} /> ADMIN
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)]">
                          <ShieldOff size={10} /> User
                        </span>
                      )}
                      <button
                        onClick={() => handleDisconnect(agent.agent_id)}
                        className="p-1 rounded text-[var(--color-text-muted)] hover:text-[var(--color-red)] hover:bg-[var(--color-bg-tertiary)]"
                        title="Disconnect"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                    <div>
                      <span className="text-[var(--color-text-muted)]">User: </span>
                      <span className="text-[var(--color-text-secondary)]">
                        {agent.domain}\{agent.username}
                      </span>
                    </div>
                    <div>
                      <span className="text-[var(--color-text-muted)]">Uptime: </span>
                      <span className="text-[var(--color-text-secondary)]">
                        {formatUptime(agent.connected_seconds)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[var(--color-text-muted)]">IP: </span>
                      <span className="text-[var(--color-text-secondary)] font-mono">
                        {agent.ip_addresses.slice(0, 2).join(", ")}
                      </span>
                    </div>
                    <div>
                      <span className="text-[var(--color-text-muted)]">OS: </span>
                      <span className="text-[var(--color-text-secondary)]">
                        {agent.os_version}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="px-4 py-3 border-t border-[var(--color-border)]">
          <p className="text-[10px] text-[var(--color-text-muted)]">
            The AI can interact with connected agents using run_powershell, query_ad, run_csharp, and get_system_info tools in chat.
          </p>
        </div>
      </div>
    </div>
  );
}
