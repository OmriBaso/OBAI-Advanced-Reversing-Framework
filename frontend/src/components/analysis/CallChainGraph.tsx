import { useEffect, useRef, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { useChainStore } from "../../stores/chainStore";
import { apiClient } from "../../api/client";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { ZoomIn, ZoomOut, Maximize, ArrowLeft, ArrowRight, Pin } from "lucide-react";
import type { CallChainData } from "../../api/types";

cytoscape.use(dagre);

export function CallChainGraph() {
  const { sid, selectedFunction, setSelectedFunction } = useAnalysisStore();
  const { setActiveTab } = useUIStore();
  const { pinned, pin } = useChainStore();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const chainDataRef = useRef<CallChainData | null>(null);
  const chainRootRef = useRef<string>("");
  const [loading, setLoading] = useState(false);
  const [direction, setDirection] = useState<"backward" | "forward">("backward");
  const [maxDepth, setMaxDepth] = useState(8);
  const [info, setInfo] = useState<{ count: number; depth: number; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!sid || !selectedFunction || !containerRef.current) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    apiClient
      .getCallChain(sid, selectedFunction, direction, maxDepth)
      .then((data: CallChainData) => {
        if (cancelled || !containerRef.current) return;

        chainDataRef.current = data;
        chainRootRef.current = selectedFunction;

        if (cyRef.current) {
          cyRef.current.destroy();
          cyRef.current = null;
        }

        const cy = cytoscape({
          container: containerRef.current,
          elements: [...data.nodes, ...data.edges],
          style: [
            {
              selector: "node",
              style: {
                label: "data(label)",
                "text-valign": "center",
                "text-halign": "center",
                "font-size": "10px",
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
              selector: 'node[?is_root]',
              style: { "border-color": "#d29922", "border-width": 3, "background-color": "#2a2010" },
            },
            {
              selector: 'node[?is_import]',
              style: { "border-color": "#a371f7", "border-width": 2 },
            },
            {
              selector: "edge",
              style: {
                width: 1.5,
                "line-color": "#8b949e",
                "target-arrow-color": "#8b949e",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "arrow-scale": 0.9,
              },
            },
          ],
          layout: {
            name: "dagre",
            rankDir: direction === "backward" ? "BT" : "TB",
            nodeSep: 30,
            rankSep: 60,
          } as cytoscape.LayoutOptions,
          userZoomingEnabled: true,
          userPanningEnabled: true,
          boxSelectionEnabled: false,
        });

        cy.on("dbltap", "node", (evt) => {
          const node = evt.target;
          const name = node.data("name") as string;
          if (!name) return;
          // Auto-pin the current chain on first navigation so the user
          // can keep jumping without losing context. Explicit pin button
          // is the other way in.
          if (chainDataRef.current && !useChainStore.getState().pinned) {
            pin(chainDataRef.current, chainRootRef.current, direction);
          }
          setSelectedFunction(name);
          setActiveTab("pseudocode");
        });

        cyRef.current = cy;
        setInfo({
          count: data.nodes.length,
          depth: data.depth_reached,
          truncated: data.truncated,
        });
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message || "Failed to load call chain");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [sid, selectedFunction, direction, maxDepth, setSelectedFunction, setActiveTab, pin]);

  const handlePin = () => {
    if (chainDataRef.current) {
      pin(chainDataRef.current, chainRootRef.current, direction);
    }
  };

  if (!selectedFunction) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-[var(--color-text-muted)]">
        Select a function to track its call chain
      </div>
    );
  }

  return (
    <div className="h-full relative">
      <div className="absolute top-2 left-2 z-10 flex items-center gap-2 bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded px-2 py-1">
        <button
          onClick={() => setDirection("backward")}
          className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded transition-colors ${
            direction === "backward"
              ? "bg-[var(--color-accent)] text-white"
              : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
          title="Show callers (upstream)"
        >
          <ArrowLeft size={10} /> Backward
        </button>
        <button
          onClick={() => setDirection("forward")}
          className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded transition-colors ${
            direction === "forward"
              ? "bg-[var(--color-accent)] text-white"
              : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
          title="Show callees (downstream)"
        >
          Forward <ArrowRight size={10} />
        </button>
        <div className="w-px h-4 bg-[var(--color-border)]" />
        <label
          className="text-[10px] text-[var(--color-text-muted)]"
          title="Number of call-graph hops to walk. Every sibling caller within a layer is always shown — this controls depth, not breadth."
        >
          Layers
        </label>
        <input
          type="number"
          min={1}
          max={30}
          value={maxDepth}
          onChange={(e) => setMaxDepth(Math.max(1, Math.min(30, parseInt(e.target.value) || 1)))}
          className="w-12 px-1 py-0.5 text-[10px] bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
          title="Each layer = one call-graph hop. 1 = direct callers only."
        />
      </div>

      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-[var(--color-bg-primary)] bg-opacity-80 z-10">
          <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
            <div className="w-4 h-4 border-2 border-[var(--color-accent)] border-t-transparent rounded-full animate-spin" />
            Tracing chain...
          </div>
        </div>
      )}

      {error && !loading && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-[var(--color-red)]">
          {error}
        </div>
      )}

      <div ref={containerRef} className="h-full w-full" />

      <div className="absolute top-2 right-2 flex flex-col gap-1 z-10">
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
        <button
          onClick={handlePin}
          disabled={!chainDataRef.current}
          className={`p-1.5 rounded border transition-colors disabled:opacity-50 ${
            pinned && pinned.rootFunction === chainRootRef.current
              ? "bg-[var(--color-accent)] border-[var(--color-accent)] text-white"
              : "bg-[var(--color-bg-tertiary)] border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
          title="Pin this chain to a floating window so you can keep jumping after navigating"
        >
          <Pin size={14} />
        </button>
      </div>

      {info && (
        <div className="absolute bottom-2 left-2 flex items-center gap-3 text-[10px] text-[var(--color-text-muted)] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded px-2 py-1">
          <span>{info.count} functions</span>
          <span>{info.depth} layer{info.depth === 1 ? "" : "s"}</span>
          {info.truncated && (
            <span
              className="text-[var(--color-yellow)]"
              title="Hit the layer cap — raise the Layers input to see more"
            >
              truncated (raise layers)
            </span>
          )}
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded border-2 border-[var(--color-yellow)]" /> root
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded border-2 border-[var(--color-purple)]" /> import
          </span>
          <span className="text-[var(--color-text-muted)]">double-click a node to jump</span>
        </div>
      )}
    </div>
  );
}
