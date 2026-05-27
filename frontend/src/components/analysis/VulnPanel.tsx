import { useAnalysisStore } from "../../stores/analysisStore";
import { useChatStore } from "../../stores/chatStore";
import { AlertTriangle, Zap } from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-[var(--color-red)] text-white",
  high: "bg-[var(--color-orange)] text-white",
  medium: "bg-yellow-600 text-white",
  low: "bg-[var(--color-text-muted)] text-white",
};

export function VulnPanel() {
  const { sid, vulnerabilities } = useAnalysisStore();
  const { generateExploit, isStreaming } = useChatStore();

  if (!vulnerabilities.length) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-[var(--color-text-muted)]">
        <div className="text-center">
          <AlertTriangle size={32} className="mx-auto mb-2 opacity-40" />
          <p>No vulnerabilities discovered yet.</p>
          <p className="text-xs mt-1">Use Free Roam or ask the AI to scan for vulnerabilities.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <div className="divide-y divide-[var(--color-border-light)]">
        {vulnerabilities.map((vuln) => (
          <div key={vuln.id} className="p-4 hover:bg-[var(--color-bg-tertiary)] transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${SEVERITY_COLORS[vuln.severity] || ""}`}>
                    {vuln.severity.toUpperCase()}
                  </span>
                  <span className="text-sm font-medium text-[var(--color-text-primary)]">{vuln.name}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-[var(--color-text-secondary)] mb-2">
                  <span className="font-mono">{vuln.function}</span>
                  <span className="px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)]">{vuln.classification}</span>
                </div>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">{vuln.description}</p>
              </div>

              <button
                onClick={() => generateExploit(sid, vuln.id)}
                disabled={isStreaming}
                className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[var(--color-red)] text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
              >
                <Zap size={12} />
                {vuln.exploit_code ? "Regenerate" : "Generate"} Exploit
              </button>
            </div>

            {vuln.exploit_code && (
              <div className="mt-3 rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] overflow-auto max-h-40">
                <pre className="p-3 text-xs font-mono text-[var(--color-text-secondary)]">
                  {vuln.exploit_code.slice(0, 1000)}
                  {vuln.exploit_code.length > 1000 && "..."}
                </pre>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
