import { useEffect, useRef, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { apiClient } from "../../api/client";
import cytoscape from "cytoscape";
import { ZoomIn, ZoomOut, Maximize } from "lucide-react";

export function CFGGraph() {
  const { sid, selectedFunction, selectedFunctionModule } = useAnalysisStore();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!sid || !selectedFunction || !containerRef.current) return;

    setLoading(true);
    apiClient
      .getCfg(sid, selectedFunction, selectedFunctionModule || undefined)
      .then((data) => {
        if (cyRef.current) {
          cyRef.current.destroy();
        }

        const cy = cytoscape({
          container: containerRef.current,
          elements: [
            ...(data.nodes as cytoscape.ElementDefinition[]),
            ...(data.edges as cytoscape.ElementDefinition[]),
          ],
          style: [
            {
              selector: "node",
              style: {
                label: "data(label)",
                "text-wrap": "wrap",
                "text-valign": "center",
                "text-halign": "center",
                "font-size": "9px",
                "font-family": "JetBrains Mono, monospace",
                color: "#e6edf3",
                "background-color": "#21262d",
                "border-width": 1,
                "border-color": "#30363d",
                shape: "roundrectangle",
                width: "label",
                height: "label",
                padding: "10px",
              },
            },
            {
              selector: 'node[type="entry"]',
              style: { "border-color": "#3fb950", "border-width": 2 },
            },
            {
              selector: 'node[type="exit"]',
              style: { "border-color": "#f85149", "border-width": 2 },
            },
            {
              selector: 'node[type="branch"]',
              style: { "border-color": "#d29922", "border-width": 2 },
            },
            {
              selector: 'node[type="call"]',
              style: { "border-color": "#58a6ff", "border-width": 2 },
            },
            {
              selector: "edge",
              style: {
                width: 1.5,
                "line-color": "#8b949e",
                "target-arrow-color": "#8b949e",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "arrow-scale": 0.8,
              },
            },
          ],
          layout: {
            name: "breadthfirst",
            directed: true,
            spacingFactor: 1.5,
          },
          userZoomingEnabled: true,
          userPanningEnabled: true,
          boxSelectionEnabled: false,
        });

        cyRef.current = cy;
      })
      .catch(() => {})
      .finally(() => setLoading(false));

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [sid, selectedFunction, selectedFunctionModule]);

  if (!selectedFunction) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-[var(--color-text-muted)]">
        Select a function to view its control flow graph
      </div>
    );
  }

  return (
    <div className="h-full relative">
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-[var(--color-bg-primary)] bg-opacity-80 z-10">
          <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
            <div className="w-4 h-4 border-2 border-[var(--color-accent)] border-t-transparent rounded-full animate-spin" />
            Loading CFG...
          </div>
        </div>
      )}

      <div ref={containerRef} className="h-full w-full" />

      <div className="absolute top-2 right-2 flex flex-col gap-1">
        <button
          onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)}
          className="p-1.5 rounded bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <ZoomIn size={14} />
        </button>
        <button
          onClick={() => cyRef.current?.zoom(cyRef.current.zoom() / 1.2)}
          className="p-1.5 rounded bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <ZoomOut size={14} />
        </button>
        <button
          onClick={() => cyRef.current?.fit()}
          className="p-1.5 rounded bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <Maximize size={14} />
        </button>
      </div>

      <div className="absolute bottom-2 left-2 flex gap-3 text-[10px] text-[var(--color-text-muted)]">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded border-2 border-[var(--color-green)]" /> Entry</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded border-2 border-[var(--color-red)]" /> Exit</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded border-2 border-[var(--color-orange)]" /> Branch</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded border-2 border-[var(--color-accent)]" /> Call</span>
      </div>
    </div>
  );
}
