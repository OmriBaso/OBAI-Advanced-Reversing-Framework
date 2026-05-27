import { Header } from "./components/layout/Header";
import { Sidebar } from "./components/layout/Sidebar";
import { AnalysisPanel } from "./components/layout/AnalysisPanel";
import { ChatPanel } from "./components/chat/ChatPanel";
import { ConfigModal } from "./components/shared/ConfigModal";
import { DatabaseModal } from "./components/shared/DatabaseModal";
import { DependencyModal } from "./components/upload/DependencyModal";
import { XRefModal } from "./components/analysis/XRefModal";
import { FloatingChainPanel } from "./components/analysis/FloatingChainPanel";
import { AgentPanel } from "./components/shared/AgentPanel";
import { ExportModal } from "./components/shared/ExportModal";
import { ExitSessionModal } from "./components/shared/ExitSessionModal";
import { AddBinaryModal } from "./components/upload/AddBinaryModal";
import { useUIStore } from "./stores/uiStore";
import { useAnalysisStore } from "./stores/analysisStore";
import { useRef, useCallback, useEffect } from "react";

export default function App() {
  const { sidebarWidth, chatHeight, setSidebarWidth, setChatHeight, activeModal } = useUIStore();
  const sid = useAnalysisStore((s) => s.sid);
  const restoreSession = useAnalysisStore((s) => s.restoreSession);

  const sidebarDragRef = useRef(false);
  const chatDragRef = useRef(false);

  // On first mount, try to restore a persisted sid from localStorage. The browser
  // session only ends when the user clicks "Exit Reversing Session" OR the backend
  // reports "Invalid session" — never on a simple page refresh.
  useEffect(() => {
    restoreSession();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Heartbeat: while a session is active and the tab is open, ping every 4 minutes
  // so the server's idle-TTL reaper never kills our session out from under us.
  useEffect(() => {
    if (!sid) return;
    const ping = () => {
      fetch(`/api/analysis/${sid}/ping`).catch(() => {});
    };
    ping();
    const id = window.setInterval(ping, 4 * 60 * 1000);
    const onVisible = () => {
      if (document.visibilityState === "visible") ping();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [sid]);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (sidebarDragRef.current) {
        setSidebarWidth(Math.max(200, Math.min(500, e.clientX)));
      }
      if (chatDragRef.current) {
        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
        setChatHeight(Math.max(200, Math.min(600, rect.bottom - e.clientY)));
      }
    },
    [setSidebarWidth, setChatHeight]
  );

  const handleMouseUp = useCallback(() => {
    sidebarDragRef.current = false;
    chatDragRef.current = false;
  }, []);

  return (
    <div
      className="flex flex-col h-screen"
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      <Header />

      <div className="flex flex-1 overflow-hidden">
        <div style={{ width: sidebarWidth }} className="flex-shrink-0 border-r border-[var(--color-border)]">
          <Sidebar />
        </div>

        <div
          className="w-1 cursor-col-resize bg-[var(--color-border)] hover:bg-[var(--color-accent)] transition-colors"
          onMouseDown={() => { sidebarDragRef.current = true; }}
        />

        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex-1 overflow-hidden">
            <AnalysisPanel />
          </div>

          {sid && (
            <>
              <div
                className="h-1 cursor-row-resize bg-[var(--color-border)] hover:bg-[var(--color-accent)] transition-colors"
                onMouseDown={() => { chatDragRef.current = true; }}
              />
              <div style={{ height: chatHeight }} className="flex-shrink-0">
                <ChatPanel />
              </div>
            </>
          )}
        </div>
      </div>

      {activeModal === "config" && <ConfigModal />}
      {activeModal === "databases" && <DatabaseModal />}
      {activeModal === "dependencies" && <DependencyModal />}
      {activeModal === "agents" && <AgentPanel />}
      {activeModal === "exportSelect" && <ExportModal />}
      {(activeModal === "xrefs" || activeModal === "callers" || activeModal === "callees") && <XRefModal />}
      {activeModal === "exitSession" && <ExitSessionModal />}
      {activeModal === "addBinary" && <AddBinaryModal />}

      <FloatingChainPanel />
    </div>
  );
}
