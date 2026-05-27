import { useEffect, useRef, useCallback } from "react";
import { useChainStore } from "../../stores/chainStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { X, GripHorizontal } from "lucide-react";

cytoscape.use(dagre);

const MIN_WIDTH = 280;
const MIN_HEIGHT = 220;
const HEADER_HEIGHT = 32;

export function FloatingChainPanel() {
  const { pinned, position, size, unpin, setPosition, setSize } = useChainStore();
  const { selectedFunction, setSelectedFunction } = useAnalysisStore();
  const { setActiveTab } = useUIStore();

  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; ox: number; oy: number } | null>(null);
  const resizeRef = useRef<{ startX: number; startY: number; ow: number; oh: number } | null>(null);

  const bodyWidth = size.width;
  const bodyHeight = Math.max(0, size.height - HEADER_HEIGHT);

  useEffect(() => {
    if (!pinned) return;
    const container = containerRef.current;
    if (!container) return;

    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    let rafId = 0;
    let ro: ResizeObserver | null = null;

    const init = () => {
      const c = containerRef.current;
      if (!c || !c.isConnected) return;
      if (c.clientWidth === 0 || c.clientHeight === 0) {
        rafId = requestAnimationFrame(init);
        return;
      }

      const nodeCount = pinned.data.nodes?.length ?? 0;
      const edgeCount = pinned.data.edges?.length ?? 0;
      // eslint-disable-next-line no-console
      console.log("[FloatingChainPanel] init", {
        width: c.clientWidth,
        height: c.clientHeight,
        nodes: nodeCount,
        edges: edgeCount,
        direction: pinned.direction,
      });

      if (nodeCount === 0) {
        return;
      }

      let cy: cytoscape.Core;
      try {
        cy = cytoscape({
          container: c,
          elements: [...pinned.data.nodes, ...pinned.data.edges],
          style: [
            {
              selector: "node",
              style: {
                label: "data(label)",
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
                padding: "6px",
              },
            },
            {
              selector: "node[?is_root]",
              style: { "border-color": "#d29922", "border-width": 2, "background-color": "#2a2010" },
            },
            {
              selector: "node[?is_import]",
              style: { "border-color": "#a371f7", "border-width": 2 },
            },
            {
              selector: "node.current",
              style: { "border-color": "#3fb950", "border-width": 3, "background-color": "#0d2818" },
            },
            {
              selector: "edge",
              style: {
                width: 1,
                "line-color": "#8b949e",
                "target-arrow-color": "#8b949e",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "arrow-scale": 0.8,
              },
            },
          ],
          userZoomingEnabled: true,
          userPanningEnabled: true,
          boxSelectionEnabled: false,
        });
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("[FloatingChainPanel] cytoscape init failed", e);
        return;
      }

      cyRef.current = cy;

      cy.on("dbltap", "node", (evt) => {
        const name = evt.target.data("name") as string;
        if (!name) return;
        setSelectedFunction(name);
        setActiveTab("pseudocode");
      });

      // Run layout explicitly and fit only after it has positioned the nodes.
      const layout = cy.layout({
        name: "dagre",
        rankDir: pinned.direction === "backward" ? "BT" : "TB",
        nodeSep: 20,
        rankSep: 40,
        fit: false,
      } as cytoscape.LayoutOptions);

      cy.one("layoutstop", () => {
        cy.resize();
        cy.fit(cy.elements(), 20);
      });

      layout.run();

      // Fallback if layoutstop never fires (e.g. dagre not registered for some reason)
      setTimeout(() => {
        if (cyRef.current === cy) {
          cy.resize();
          if (cy.elements().length > 0) cy.fit(cy.elements(), 20);
        }
      }, 250);

      ro = new ResizeObserver(() => {
        if (cyRef.current) {
          cyRef.current.resize();
        }
      });
      ro.observe(c);
    };

    rafId = requestAnimationFrame(init);

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      if (ro) ro.disconnect();
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [pinned, setSelectedFunction, setActiveTab]);

  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.nodes().removeClass("current");
    if (selectedFunction) {
      cyRef.current
        .nodes()
        .filter((n) => n.data("name") === selectedFunction)
        .addClass("current");
    }
  }, [selectedFunction, pinned]);

  const onHeaderMouseDown = (e: React.MouseEvent) => {
    dragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      ox: position.x,
      oy: position.y,
    };
    e.preventDefault();
  };

  const onResizeMouseDown = (e: React.MouseEvent) => {
    resizeRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      ow: size.width,
      oh: size.height,
    };
    e.preventDefault();
    e.stopPropagation();
  };

  const onMouseMove = useCallback(
    (e: MouseEvent) => {
      if (dragRef.current) {
        const { startX, startY, ox, oy } = dragRef.current;
        const nx = Math.max(0, Math.min(window.innerWidth - 100, ox + (e.clientX - startX)));
        const ny = Math.max(0, Math.min(window.innerHeight - 40, oy + (e.clientY - startY)));
        setPosition(nx, ny);
      } else if (resizeRef.current) {
        const { startX, startY, ow, oh } = resizeRef.current;
        const nw = Math.max(MIN_WIDTH, ow + (e.clientX - startX));
        const nh = Math.max(MIN_HEIGHT, oh + (e.clientY - startY));
        setSize(nw, nh);
        if (cyRef.current) cyRef.current.resize();
      }
    },
    [setPosition, setSize]
  );

  const onMouseUp = useCallback(() => {
    const wasResizing = resizeRef.current !== null;
    dragRef.current = null;
    resizeRef.current = null;
    if (cyRef.current && wasResizing) {
      // Only re-measure the canvas. Do NOT call cy.fit() — that would clobber
      // any pan/zoom the user has done inside the chain graph.
      cyRef.current.resize();
    }
  }, []);

  useEffect(() => {
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [onMouseMove, onMouseUp]);

  if (!pinned) return null;

  const nodeCount = pinned.data.nodes?.length ?? 0;

  return (
    <div
      style={{
        position: "fixed",
        left: position.x,
        top: position.y,
        width: size.width,
        height: size.height,
        zIndex: 60,
      }}
      className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-md shadow-2xl overflow-hidden"
    >
      <div
        onMouseDown={onHeaderMouseDown}
        style={{ height: HEADER_HEIGHT }}
        className="flex items-center justify-between px-2 border-b border-[var(--color-border)] bg-[var(--color-bg-tertiary)] cursor-move select-none"
      >
        <div className="flex items-center gap-2 min-w-0">
          <GripHorizontal size={12} className="text-[var(--color-text-muted)] flex-shrink-0" />
          <span className="text-[10px] font-semibold text-[var(--color-text-secondary)] flex-shrink-0">
            Chain ({pinned.direction})
          </span>
          <span
            className="text-[10px] font-mono text-[var(--color-accent)] truncate"
            title={pinned.rootFunction}
          >
            {pinned.rootFunction}
          </span>
        </div>
        <button
          onClick={unpin}
          className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] flex-shrink-0 ml-2"
          title="Close pinned chain"
        >
          <X size={14} />
        </button>
      </div>

      <div style={{ position: "relative", width: bodyWidth, height: bodyHeight }}>
        <div ref={containerRef} style={{ width: "100%", height: "100%" }} />
        {nodeCount === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-[10px] text-[var(--color-text-muted)]">
            (Pinned chain is empty — re-pin from the Chain tab)
          </div>
        )}
        <div className="absolute bottom-1 left-2 text-[9px] text-[var(--color-text-muted)] pointer-events-none">
          double-click a node to jump · drag header to move
        </div>
        <div
          onMouseDown={onResizeMouseDown}
          className="absolute bottom-0 right-0 w-3 h-3 cursor-nwse-resize"
          style={{
            background:
              "linear-gradient(135deg, transparent 50%, var(--color-text-muted) 50%, var(--color-text-muted) 60%, transparent 60%)",
          }}
        />
      </div>
    </div>
  );
}
