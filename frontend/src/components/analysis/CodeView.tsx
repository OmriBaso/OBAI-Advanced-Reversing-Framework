import { useEffect, useMemo, useRef, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { apiClient } from "../../api/client";
import { useUIStore } from "../../stores/uiStore";
import { RenameContextMenu } from "./RenameContextMenu";
import hljs from "highlight.js/lib/core";
import c from "highlight.js/lib/languages/c";
import "highlight.js/styles/atom-one-dark.css";

hljs.registerLanguage("c", c);

interface MenuState {
  kind: "func" | "var" | "symbol";
  name: string;
  x: number;
  y: number;
}

// Identifiers Ghidra emits for global data references. Matched against tokens
// that aren't already known as a function or variable in the current scope.
const GLOBAL_SYMBOL_RX = /^(?:DAT|PTR|OFF|unk|s|u|w|FLOAT|DOUBLE|LAB|SUB|EXT|BYTE)_[A-Za-z0-9_]*[0-9a-fA-F]{2,}$/;

const C_KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "default", "break", "continue",
  "return", "goto", "void", "int", "char", "short", "long", "float", "double", "signed",
  "unsigned", "const", "static", "extern", "register", "volatile", "struct", "union",
  "enum", "typedef", "sizeof", "auto", "inline", "restrict",
  "true", "false", "NULL", "null", "this",
  // Ghidra common pseudo-types
  "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
  "byte", "word", "dword", "qword", "longlong", "ulonglong", "ushort", "uint", "ulong",
  "bool", "pointer", "string", "wchar_t", "BOOL", "DWORD", "WORD", "BYTE", "LPVOID",
  "HANDLE", "HRESULT", "LONG", "ULONG", "PVOID", "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR",
]);

export function CodeView() {
  const {
    sid,
    selectedFunction,
    selectedFunctionModule,
    functions,
    pseudocodeVersion,
    setSelectedFunction,
    renameFunction,
    renameVariable,
    renameSymbol,
  } = useAnalysisStore();
  const { setActiveTab } = useUIStore();
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [variables, setVariables] = useState<{ params: string[]; locals: string[] }>({
    params: [],
    locals: [],
  });
  const [menu, setMenu] = useState<MenuState | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Fetch pseudocode whenever selection or version (rename-triggered) changes
  useEffect(() => {
    if (!sid || !selectedFunction) {
      setCode("");
      setVariables({ params: [], locals: [] });
      return;
    }
    setLoading(true);
    setMenu(null);
    apiClient
      .getPseudocode(sid, selectedFunction, selectedFunctionModule || undefined)
      .then((r) => setCode(r.pseudocode))
      .catch((e) => setCode(`// Error: ${e.message}`))
      .finally(() => setLoading(false));
    apiClient
      .getFunctionVariables(sid, selectedFunction, selectedFunctionModule || undefined)
      .then((r) =>
        setVariables({
          params: r.params.map((p) => p.name),
          locals: r.locals.map((v) => v.name),
        })
      )
      .catch(() => setVariables({ params: [], locals: [] }));
  }, [sid, selectedFunction, selectedFunctionModule, pseudocodeVersion]);

  // Build the identifier sets used to mark rename-targets
  const funcNames = useMemo(() => {
    const s = new Set<string>();
    for (const f of functions) {
      if (selectedFunctionModule && f.module && f.module !== selectedFunctionModule) continue;
      s.add(f.name);
    }
    return s;
  }, [functions, selectedFunctionModule]);

  const varNames = useMemo(() => new Set([...variables.params, ...variables.locals]), [variables]);

  // After mount, walk text nodes to wrap identifier tokens in <span data-rename …>
  useEffect(() => {
    const root = containerRef.current?.querySelector("code");
    if (!root || !code) return;

    const tokenRx = /\b([A-Za-z_][A-Za-z0-9_]*)\b/g;

    const walkAndWrap = (node: Node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        const text = node.nodeValue || "";
        let lastIndex = 0;
        let match: RegExpExecArray | null;
        const frag: (Node | string)[] = [];
        tokenRx.lastIndex = 0;
        while ((match = tokenRx.exec(text)) !== null) {
          const word = match[1];
          if (C_KEYWORDS.has(word)) continue;
          const isFunc = funcNames.has(word);
          const isVar = !isFunc && varNames.has(word);
          const isSymbol = !isFunc && !isVar && GLOBAL_SYMBOL_RX.test(word);
          if (!isFunc && !isVar && !isSymbol) continue;
          if (match.index > lastIndex) frag.push(text.slice(lastIndex, match.index));
          const span = document.createElement("span");
          span.dataset.rename = "1";
          span.dataset.kind = isFunc ? "func" : isVar ? "var" : "symbol";
          span.dataset.name = word;
          span.textContent = word;
          span.className = isFunc
            ? "rename-target-func"
            : isVar
            ? "rename-target-var"
            : "rename-target-symbol";
          frag.push(span);
          lastIndex = match.index + word.length;
        }
        if (frag.length === 0) return;
        if (lastIndex < text.length) frag.push(text.slice(lastIndex));
        const parent = node.parentNode!;
        for (const piece of frag) {
          if (typeof piece === "string") {
            parent.insertBefore(document.createTextNode(piece), node);
          } else {
            parent.insertBefore(piece, node);
          }
        }
        parent.removeChild(node);
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        // Don't recurse into already-wrapped spans
        const el = node as Element;
        if ((el as HTMLElement).dataset?.rename) return;
        for (const child of Array.from(node.childNodes)) walkAndWrap(child);
      }
    };

    walkAndWrap(root);
  }, [code, funcNames, varNames]);

  const onContextMenu = (e: React.MouseEvent) => {
    const target = (e.target as HTMLElement).closest<HTMLElement>("[data-rename]");
    if (!target) return;
    e.preventDefault();
    const kind = target.dataset.kind as "func" | "var" | "symbol";
    const name = target.dataset.name || "";
    if (!name) return;
    setMenu({ kind, name, x: e.clientX, y: e.clientY });
  };

  if (!selectedFunction) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-[var(--color-text-muted)]">
        Select a function from the sidebar
      </div>
    );
  }

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <div className="w-4 h-4 border-2 border-[var(--color-accent)] border-t-transparent rounded-full animate-spin" />
          Decompiling {selectedFunction}...
        </div>
      </div>
    );
  }

  const highlighted = code ? hljs.highlight(code, { language: "c" }).value : "";
  const lines = code.split("\n");

  return (
    <div
      ref={containerRef}
      className="h-full overflow-auto font-mono text-xs"
      onContextMenu={onContextMenu}
    >
      <div className="flex">
        <div className="flex-shrink-0 text-right pr-3 pl-2 py-3 text-[var(--color-text-muted)] select-none border-r border-[var(--color-border-light)] bg-[var(--color-bg-secondary)]">
          {lines.map((_, i) => (
            <div key={i} className="leading-5">
              {i + 1}
            </div>
          ))}
        </div>
        <pre className="flex-1 p-3 overflow-x-auto">
          <code
            className="hljs language-c leading-5"
            dangerouslySetInnerHTML={{ __html: highlighted }}
          />
        </pre>
      </div>

      {menu && (
        <RenameContextMenu
          kind={menu.kind}
          name={menu.name}
          x={menu.x}
          y={menu.y}
          canJump={menu.kind === "func" && menu.name !== selectedFunction && funcNames.has(menu.name)}
          onJump={() => {
            const entry = functions.find(
              (f) =>
                f.name === menu.name &&
                (!selectedFunctionModule || f.module === selectedFunctionModule)
            );
            setSelectedFunction(menu.name, entry?.module);
            setActiveTab("pseudocode");
          }}
          onCommit={async (newName) => {
            if (menu.kind === "func") {
              await renameFunction(menu.name, newName, selectedFunctionModule || undefined);
            } else if (menu.kind === "var") {
              await renameVariable(selectedFunction, menu.name, newName, selectedFunctionModule || undefined);
            } else {
              await renameSymbol(menu.name, newName, selectedFunctionModule || undefined);
            }
          }}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  );
}
