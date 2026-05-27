import { useState, useEffect } from "react";
import { useUIStore } from "../../stores/uiStore";
import { apiClient } from "../../api/client";
import { X, Save } from "lucide-react";

interface ProviderConfig {
  api_key?: string;
  model?: string;
  base_url?: string;
  thinking_budget?: number;
}

export function ConfigModal() {
  const { closeModal } = useUIStore();
  const [activeProvider, setActiveProvider] = useState("anthropic");
  const [providers, setProviders] = useState<Record<string, ProviderConfig>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    apiClient
      .getConfig()
      .then((cfg) => {
        setActiveProvider(cfg.active_provider);
        setProviders(cfg.providers);
      })
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await apiClient.setConfig({ active_provider: activeProvider, providers });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } finally {
      setSaving(false);
    }
  };

  const updateProvider = (name: string, key: string, value: string) => {
    setProviders((prev) => ({
      ...prev,
      [name]: { ...prev[name], [key]: value },
    }));
  };

  const setThinkingEnabled = (enabled: boolean) => {
    setProviders((prev) => {
      const current = Number(prev.anthropic?.thinking_budget ?? 0);
      const next = enabled ? (current > 0 ? current : 6000) : 0;
      return { ...prev, anthropic: { ...prev.anthropic, thinking_budget: next } };
    });
  };

  const PROVIDERS = [
    { id: "anthropic", label: "Anthropic", hasKey: true, hasUrl: false },
    { id: "openai", label: "OpenAI", hasKey: true, hasUrl: false },
    { id: "ollama", label: "Ollama (Local)", hasKey: false, hasUrl: true },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeModal}>
      <div
        className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg w-[500px] shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold">Settings</h3>
          <button onClick={closeModal} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]">
            <X size={16} />
          </button>
        </div>

        {loading ? (
          <div className="p-6 text-center text-sm text-[var(--color-text-secondary)]">Loading...</div>
        ) : (
          <div className="p-4 space-y-4">
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-secondary)] mb-1.5">
                Active Provider
              </label>
              <div className="flex gap-2">
                {PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => setActiveProvider(p.id)}
                    className={`flex-1 py-2 text-xs rounded transition-colors ${
                      activeProvider === p.id
                        ? "bg-[var(--color-accent)] text-white"
                        : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            {PROVIDERS.map((p) => (
              <div
                key={p.id}
                className={`space-y-2 p-3 rounded border ${
                  activeProvider === p.id
                    ? "border-[var(--color-accent)] bg-[var(--color-bg-tertiary)]"
                    : "border-[var(--color-border)] opacity-50"
                }`}
              >
                <div className="text-xs font-medium text-[var(--color-text-primary)]">{p.label}</div>

                <div>
                  <label className="text-[10px] text-[var(--color-text-muted)]">Model</label>
                  <input
                    type="text"
                    value={providers[p.id]?.model || ""}
                    onChange={(e) => updateProvider(p.id, "model", e.target.value)}
                    placeholder={p.id === "anthropic" ? "claude-sonnet-4-6-20250514" : p.id === "openai" ? "gpt-4o" : "llama3"}
                    className="w-full mt-0.5 px-2 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  />
                </div>

                {p.hasKey && (
                  <div>
                    <label className="text-[10px] text-[var(--color-text-muted)]">API Key</label>
                    <input
                      type="password"
                      value={providers[p.id]?.api_key || ""}
                      onChange={(e) => updateProvider(p.id, "api_key", e.target.value)}
                      placeholder="Enter API key..."
                      className="w-full mt-0.5 px-2 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                )}

                {p.id === "anthropic" && (() => {
                  const budget = Number(providers[p.id]?.thinking_budget ?? 0);
                  const enabled = budget > 0;
                  return (
                    <div className="space-y-1.5">
                      <label className="flex items-center gap-2 text-xs text-[var(--color-text-primary)] cursor-pointer">
                        <input
                          type="checkbox"
                          checked={enabled}
                          onChange={(e) => setThinkingEnabled(e.target.checked)}
                          className="cursor-pointer"
                        />
                        Enable thinking (extended reasoning)
                      </label>
                      <p className="text-[9px] text-[var(--color-text-muted)] leading-tight">
                        Thinking tokens are billed as output tokens. Disable to cut cost; enable for harder reasoning tasks.
                      </p>
                      <div className={enabled ? "" : "opacity-40 pointer-events-none"}>
                        <label className="text-[10px] text-[var(--color-text-muted)]">
                          Thinking budget (tokens)
                        </label>
                        <input
                          type="number"
                          min={1024}
                          max={100000}
                          step={1000}
                          value={enabled ? budget : 6000}
                          onChange={(e) => updateProvider(p.id, "thinking_budget", e.target.value)}
                          className="w-full mt-0.5 px-2 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                        />
                      </div>
                    </div>
                  );
                })()}

                {p.hasUrl && (
                  <div>
                    <label className="text-[10px] text-[var(--color-text-muted)]">Base URL</label>
                    <input
                      type="text"
                      value={providers[p.id]?.base_url || "http://localhost:11434"}
                      onChange={(e) => updateProvider(p.id, "base_url", e.target.value)}
                      className="w-full mt-0.5 px-2 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                )}
              </div>
            ))}

            <button
              onClick={handleSave}
              disabled={saving}
              className="w-full flex items-center justify-center gap-2 py-2 rounded text-xs bg-[var(--color-accent)] text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              <Save size={12} />
              {saved ? "Saved!" : saving ? "Saving..." : "Save Settings"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
